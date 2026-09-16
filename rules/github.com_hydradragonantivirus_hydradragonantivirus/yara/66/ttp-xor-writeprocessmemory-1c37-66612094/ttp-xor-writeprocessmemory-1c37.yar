rule TTP_XOR_WriteProcessMemory_1c37 {
  strings:
    $key_1c37 = { 4b 45 [2] 79 67 [2] 7f 52 [2] 51 52 [2] 6e 4e }

  condition:
    any of them
}