rule TTP_XOR_WriteProcessMemory_db57 {
  strings:
    $key_db57 = { 8c 25 [2] be 07 [2] b8 32 [2] 96 32 [2] a9 2e }

  condition:
    any of them
}