rule apt32_macos_backdoor_2018 {
  meta:
    author = "Amnesty Tech"

  strings:
    $s1  = "respondDownloadThreadP" ascii
    $s2  = "checkProcessExist" ascii
    $s3  = "setFristRandom" ascii
    $s4  = "getInstalledTime" ascii
    $s5  = "getSerialNumber" ascii
    $s6  = "appendPathComponent" ascii
    $s7  = "initFirstRandom" ascii
    $s8  = "CFURLToString" ascii
    $s9  = "GET_DOMAIN_CLIENT_INFO" ascii
    $s10 = "getFirstRandom_Header" ascii
    $s11 = "respondLoadLunaThread" ascii

  condition:
    (uint16(0) == 0xfacf or uint16(0) == 0xface) and 9 of them
}