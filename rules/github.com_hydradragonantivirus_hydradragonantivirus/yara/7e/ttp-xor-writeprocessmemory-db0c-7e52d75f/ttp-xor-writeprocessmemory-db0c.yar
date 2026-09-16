rule TTP_XOR_WriteProcessMemory_db0c {
  strings:
    $key_db0c = { 8c 7e [2] be 5c [2] b8 69 [2] 96 69 [2] a9 75 }

  condition:
    any of them
}