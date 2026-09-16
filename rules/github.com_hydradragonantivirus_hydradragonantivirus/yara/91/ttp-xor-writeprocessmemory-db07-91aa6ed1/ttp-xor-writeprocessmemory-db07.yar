rule TTP_XOR_WriteProcessMemory_db07 {
  strings:
    $key_db07 = { 8c 75 [2] be 57 [2] b8 62 [2] 96 62 [2] a9 7e }

  condition:
    any of them
}