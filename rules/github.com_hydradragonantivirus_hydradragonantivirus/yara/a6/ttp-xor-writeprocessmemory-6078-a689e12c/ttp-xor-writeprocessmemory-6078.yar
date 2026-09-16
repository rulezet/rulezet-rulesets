rule TTP_XOR_WriteProcessMemory_6078 {
  strings:
    $key_6078 = { 37 0a [2] 05 28 [2] 03 1d [2] 2d 1d [2] 12 01 }

  condition:
    any of them
}