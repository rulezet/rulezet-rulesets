rule TTP_XOR_WriteProcessMemory_6d6c {
  strings:
    $key_6d6c = { 3a 1e [2] 08 3c [2] 0e 09 [2] 20 09 [2] 1f 15 }

  condition:
    any of them
}