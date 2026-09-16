rule TTP_XOR_WriteProcessMemory_db7e {
  strings:
    $key_db7e = { 8c 0c [2] be 2e [2] b8 1b [2] 96 1b [2] a9 07 }

  condition:
    any of them
}