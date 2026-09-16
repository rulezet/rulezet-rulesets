rule TTP_XOR_WriteProcessMemory_db49 {
  strings:
    $key_db49 = { 8c 3b [2] be 19 [2] b8 2c [2] 96 2c [2] a9 30 }

  condition:
    any of them
}