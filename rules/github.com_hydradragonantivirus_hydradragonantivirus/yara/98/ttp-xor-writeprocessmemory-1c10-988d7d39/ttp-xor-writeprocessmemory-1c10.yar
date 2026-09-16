rule TTP_XOR_WriteProcessMemory_1c10 {
  strings:
    $key_1c10 = { 4b 62 [2] 79 40 [2] 7f 75 [2] 51 75 [2] 6e 69 }

  condition:
    any of them
}