rule TTP_XOR_WriteProcessMemory_3907 {
  strings:
    $key_3907 = { 6e 75 [2] 5c 57 [2] 5a 62 [2] 74 62 [2] 4b 7e }

  condition:
    any of them
}