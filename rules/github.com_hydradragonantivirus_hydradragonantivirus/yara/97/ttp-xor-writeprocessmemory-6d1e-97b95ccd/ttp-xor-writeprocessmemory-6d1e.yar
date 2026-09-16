rule TTP_XOR_WriteProcessMemory_6d1e {
  strings:
    $key_6d1e = { 3a 6c [2] 08 4e [2] 0e 7b [2] 20 7b [2] 1f 67 }

  condition:
    any of them
}