rule TTP_XOR_WriteProcessMemory_1c07 {
  strings:
    $key_1c07 = { 4b 75 [2] 79 57 [2] 7f 62 [2] 51 62 [2] 6e 7e }

  condition:
    any of them
}