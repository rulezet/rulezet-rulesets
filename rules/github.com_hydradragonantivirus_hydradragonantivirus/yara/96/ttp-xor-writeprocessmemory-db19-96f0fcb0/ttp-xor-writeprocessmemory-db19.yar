rule TTP_XOR_WriteProcessMemory_db19 {
  strings:
    $key_db19 = { 8c 6b [2] be 49 [2] b8 7c [2] 96 7c [2] a9 60 }

  condition:
    any of them
}