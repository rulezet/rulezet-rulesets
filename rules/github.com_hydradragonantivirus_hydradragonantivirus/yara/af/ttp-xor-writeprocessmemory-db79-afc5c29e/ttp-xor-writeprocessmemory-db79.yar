rule TTP_XOR_WriteProcessMemory_db79 {
  strings:
    $key_db79 = { 8c 0b [2] be 29 [2] b8 1c [2] 96 1c [2] a9 00 }

  condition:
    any of them
}