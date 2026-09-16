rule TTP_XOR_WriteProcessMemory_db67 {
  strings:
    $key_db67 = { 8c 15 [2] be 37 [2] b8 02 [2] 96 02 [2] a9 1e }

  condition:
    any of them
}