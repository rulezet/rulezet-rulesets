rule TTP_XOR_WriteProcessMemory_db36 {
  strings:
    $key_db36 = { 8c 44 [2] be 66 [2] b8 53 [2] 96 53 [2] a9 4f }

  condition:
    any of them
}