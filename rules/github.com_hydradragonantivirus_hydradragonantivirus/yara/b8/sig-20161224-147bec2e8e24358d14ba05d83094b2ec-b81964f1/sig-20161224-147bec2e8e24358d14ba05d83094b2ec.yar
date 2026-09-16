rule sig_20161224_147bec2e8e24358d14ba05d83094b2ec {
  meta:
    description = "datamaliciousorder - file 20161224_147bec2e8e24358d14ba05d83094b2ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4244425170edea123f24e5a64aec448f155a606ffc945137bb95acda190afc3a"

  strings:
    $s1 = "t);\")(ykaap,null,null));" fullword ascii
    $s2 = "return (new Function(\"jyhba\",\"ujjxp\",\"jekym\",\"var udqta=jyhba.match(/\\\\S{5}/g),fanot=\\\"\\\",ertti=0;while(ertti<udqta" ascii
    $s3 = "function burtn(ykaap)" fullword ascii
    $s4 = "return banwg[Math.floor(Math['rand'+new Array('om')[0]]()*banwg.length)];" fullword ascii
    $s5 = "function cmets()" fullword ascii
    $s6 = "return ifgbs;" fullword ascii
    $s7 = "return (new Function(\"jyhba\",\"ujjxp\",\"jekym\",\"var udqta=jyhba.match(/\\\\S{5}/g),fanot=\\\"\\\",ertti=0;while(ertti<udqta" ascii
    $s8 = "function hefzu()" fullword ascii
    $s9 = "var banwg=new Array(\"|R%\",\"g.\"+\"\"+\"f\",\"h){\",\"e(p\",\"++;\",\"].su\",\"J|X\",\"P|C\",\"|}\");" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}