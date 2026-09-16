rule TTP_XOR_WriteProcessMemory_2771 {
  strings:
    $key_2771 = { 70 03 [2] 42 21 [2] 44 14 [2] 6a 14 [2] 55 08 }

  condition:
    any of them
}