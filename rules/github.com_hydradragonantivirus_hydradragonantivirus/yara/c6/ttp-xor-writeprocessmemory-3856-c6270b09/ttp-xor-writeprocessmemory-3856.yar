rule TTP_XOR_WriteProcessMemory_3856 {
  strings:
    $key_3856 = { 6f 24 [2] 5d 06 [2] 5b 33 [2] 75 33 [2] 4a 2f }

  condition:
    any of them
}