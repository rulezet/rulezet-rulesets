rule TTP_XOR_WriteProcessMemory_4907 {
  strings:
    $key_4907 = { 1e 75 [2] 2c 57 [2] 2a 62 [2] 04 62 [2] 3b 7e }

  condition:
    any of them
}