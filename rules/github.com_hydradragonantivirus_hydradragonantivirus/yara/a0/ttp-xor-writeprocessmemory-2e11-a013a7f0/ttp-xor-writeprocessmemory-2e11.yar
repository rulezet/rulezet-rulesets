rule TTP_XOR_WriteProcessMemory_2e11 {
  strings:
    $key_2e11 = { 79 63 [2] 4b 41 [2] 4d 74 [2] 63 74 [2] 5c 68 }

  condition:
    any of them
}