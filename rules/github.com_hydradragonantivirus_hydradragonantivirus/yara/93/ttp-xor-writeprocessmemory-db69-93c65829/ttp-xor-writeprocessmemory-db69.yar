rule TTP_XOR_WriteProcessMemory_db69 {
  strings:
    $key_db69 = { 8c 1b [2] be 39 [2] b8 0c [2] 96 0c [2] a9 10 }

  condition:
    any of them
}