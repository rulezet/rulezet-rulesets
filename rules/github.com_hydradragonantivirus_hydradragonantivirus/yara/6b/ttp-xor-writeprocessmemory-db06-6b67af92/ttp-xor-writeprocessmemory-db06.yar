rule TTP_XOR_WriteProcessMemory_db06 {
  strings:
    $key_db06 = { 8c 74 [2] be 56 [2] b8 63 [2] 96 63 [2] a9 7f }

  condition:
    any of them
}