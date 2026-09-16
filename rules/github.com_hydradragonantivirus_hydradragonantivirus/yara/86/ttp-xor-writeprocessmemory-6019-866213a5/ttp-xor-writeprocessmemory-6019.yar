rule TTP_XOR_WriteProcessMemory_6019 {
  strings:
    $key_6019 = { 37 6b [2] 05 49 [2] 03 7c [2] 2d 7c [2] 12 60 }

  condition:
    any of them
}