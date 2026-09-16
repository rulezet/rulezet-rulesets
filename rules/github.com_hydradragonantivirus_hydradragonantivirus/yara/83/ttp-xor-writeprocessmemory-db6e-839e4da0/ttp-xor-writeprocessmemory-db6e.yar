rule TTP_XOR_WriteProcessMemory_db6e {
  strings:
    $key_db6e = { 8c 1c [2] be 3e [2] b8 0b [2] 96 0b [2] a9 17 }

  condition:
    any of them
}