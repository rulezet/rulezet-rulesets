rule TTP_XOR_WriteProcessMemory_db4c {
  strings:
    $key_db4c = { 8c 3e [2] be 1c [2] b8 29 [2] 96 29 [2] a9 35 }

  condition:
    any of them
}