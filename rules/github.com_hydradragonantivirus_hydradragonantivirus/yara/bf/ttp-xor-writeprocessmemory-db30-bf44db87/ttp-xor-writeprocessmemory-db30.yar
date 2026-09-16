rule TTP_XOR_WriteProcessMemory_db30 {
  strings:
    $key_db30 = { 8c 42 [2] be 60 [2] b8 55 [2] 96 55 [2] a9 49 }

  condition:
    any of them
}