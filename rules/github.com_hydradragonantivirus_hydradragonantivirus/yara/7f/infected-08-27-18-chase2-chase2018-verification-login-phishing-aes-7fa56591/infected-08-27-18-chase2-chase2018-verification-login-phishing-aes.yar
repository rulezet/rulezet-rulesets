rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_AES {
  meta:
    description = "phishing - file AES.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "b9b23ddce789047864e215fcbb411646813d9a77721d9c3ea2dc303e036431ef"

  strings:
    $s1  = "$this->cipher, $this->key, base64_decode($this->data), $this->mode, $this->getIV()));" fullword ascii
    $s2  = "$this->cipher, $this->key, $this->data, $this->mode, $this->getIV())));" fullword ascii
    $s3  = "$this->IV = mcrypt_create_iv(mcrypt_get_iv_size($this->cipher, $this->mode), MCRYPT_RAND);" fullword ascii
    $s4  = "* @param type $key" fullword ascii
    $s5  = "function __construct($data = null, $key = null, $blockSize = null, $mode = null) {" fullword ascii
    $s6  = "Created by legzy -- icq: 692561824 " fullword ascii
    $s7  = "* @param type $blockSize" fullword ascii
    $s8  = "* @param type $data" fullword ascii
    $s9  = "* @param type $mode" fullword ascii
    $s10 = "protected function getIV() {" fullword ascii
    $s11 = "public function encrypt() {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}