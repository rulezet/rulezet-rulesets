rule TTP_XOR_WriteProcessMemory_1c13 {
  strings:
    $key_1c13 = { 4b 61 [2] 79 43 [2] 7f 76 [2] 51 76 [2] 6e 6a }

  condition:
    any of them
}