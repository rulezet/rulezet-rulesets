rule TTP_XOR_WriteProcessMemory_db10 {
  strings:
    $key_db10 = { 8c 62 [2] be 40 [2] b8 75 [2] 96 75 [2] a9 69 }

  condition:
    any of them
}