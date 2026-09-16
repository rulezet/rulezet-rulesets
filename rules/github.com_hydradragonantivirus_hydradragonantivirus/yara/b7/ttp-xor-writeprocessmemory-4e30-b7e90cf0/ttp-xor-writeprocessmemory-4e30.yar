rule TTP_XOR_WriteProcessMemory_4e30 {
  strings:
    $key_4e30 = { 19 42 [2] 2b 60 [2] 2d 55 [2] 03 55 [2] 3c 49 }

  condition:
    any of them
}