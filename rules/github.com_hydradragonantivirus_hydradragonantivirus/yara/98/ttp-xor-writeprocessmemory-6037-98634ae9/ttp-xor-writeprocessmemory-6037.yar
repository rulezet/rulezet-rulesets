rule TTP_XOR_WriteProcessMemory_6037 {
  strings:
    $key_6037 = { 37 45 [2] 05 67 [2] 03 52 [2] 2d 52 [2] 12 4e }

  condition:
    any of them
}