rule TTP_XOR_WriteProcessMemory_765e {
  strings:
    $key_765e = { 21 2c [2] 13 0e [2] 15 3b [2] 3b 3b [2] 04 27 }

  condition:
    any of them
}