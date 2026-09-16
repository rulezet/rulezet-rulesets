rule TTP_XOR_WriteProcessMemory_1c31 {
  strings:
    $key_1c31 = { 4b 43 [2] 79 61 [2] 7f 54 [2] 51 54 [2] 6e 48 }

  condition:
    any of them
}