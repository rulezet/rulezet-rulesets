rule Adware_OpriUpdater_gen {
  meta:
    author  = "Kei Choi"
    date    = "2017-12-28"
    KicomAV = "AdWare.Win32.OpriUpdater.gen"

  strings:
    $string1 = /sso[a-z]+\.com/
    $string2 = "http://%s/time.php"
    $string3 = "86311%s"
    $string4 = "0123456789abcdefABCDEF%PLACEHOLDER"
    $string5 = "http://%s%s"

  condition:
    (3 of ($string1, $string2, $string3)) or (2 of ($string4, $string5))
}