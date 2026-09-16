rule TTP_XOR_WriteProcessMemory_db6c {
  strings:
    $key_db6c = { 8c 1e [2] be 3c [2] b8 09 [2] 96 09 [2] a9 15 }

  condition:
    any of them
}