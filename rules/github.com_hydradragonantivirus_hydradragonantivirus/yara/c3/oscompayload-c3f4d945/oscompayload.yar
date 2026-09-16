rule OsComPayLoad {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file OsComPayLoad.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "0827d167971390bc8c718aed98308af04a8276e8ab7839fc51f2b4713a2ee001"

  strings:
    $x1 = "$text2 = http_get('https://raw.githubusercontent.com/04x/ICG-AutoExploiterBoT/master/files/vuln.txt');" fullword ascii
    $x2 = "$text = http_get('https://raw.githubusercontent.com/Theanvenger/Tryag-File-Manager-jpeg/master/0up.php');" fullword ascii
    $s3 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/wp-content/vuln.php\" ;" fullword ascii
    $s4 = "$check2 = $_SERVER['DOCUMENT_ROOT'] . \"/vuln.htm\" ;" fullword ascii
    $s5 = "function http_get($url){" fullword ascii
    $s6 = "return curl_exec($im);" fullword ascii
    $s7 = "curl_setopt($im, CURLOPT_HEADER, 0);" fullword ascii

  condition:
    (uint16(0) == 0x743c and
      filesize < 2KB and
      (1 of ($x*) and all of them)
    ) or (all of them)
}