rule TTP_XOR_WriteProcessMemory_085e {
  strings:
    $key_085e = { 5f 2c [2] 6d 0e [2] 6b 3b [2] 45 3b [2] 7a 27 }

  condition:
    any of them
}