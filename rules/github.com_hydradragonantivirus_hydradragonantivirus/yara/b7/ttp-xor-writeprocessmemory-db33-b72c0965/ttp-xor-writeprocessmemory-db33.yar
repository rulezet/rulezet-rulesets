rule TTP_XOR_WriteProcessMemory_db33 {
  strings:
    $key_db33 = { 8c 41 [2] be 63 [2] b8 56 [2] 96 56 [2] a9 4a }

  condition:
    any of them
}