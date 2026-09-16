rule finspy_linux_installer2 {
  meta:
    description = "Rule for FinSpy Linux installer"
    author      = "Etienne Maynier, Amnesty Tech"

  strings:
    $encrypted_conf   = { 5? a5 aa ca a6 54 5a ?? a? 5a a5 0a }  
    $encrypted_bin_32 = { 7f 0d 45 4c 46 01 02 c2 14 68 03 05 0e }  
    $encrypted_bin_64 = { 7f 07 45 4c 46 02 01 1e 15 01 8e 03 0e }  

  condition:
    (uint16(0) == 0x457F or uint16(0) == 0x2123) and (#encrypted_conf > 5 or #encrypted_bin_32 > 5 or #encrypted_bin_64 > 5)
}