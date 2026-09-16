rule TTP_XOR_WriteProcessMemory_db37 {
  strings:
    $key_db37 = { 8c 45 [2] be 67 [2] b8 52 [2] 96 52 [2] a9 4e }

  condition:
    any of them
}