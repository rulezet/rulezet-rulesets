rule TTP_XOR_WriteProcessMemory_db39 {
  strings:
    $key_db39 = { 8c 4b [2] be 69 [2] b8 5c [2] 96 5c [2] a9 40 }

  condition:
    any of them
}