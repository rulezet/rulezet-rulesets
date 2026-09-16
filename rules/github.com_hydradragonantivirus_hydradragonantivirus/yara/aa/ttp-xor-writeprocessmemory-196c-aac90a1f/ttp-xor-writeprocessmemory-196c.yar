rule TTP_XOR_WriteProcessMemory_196c {
  strings:
    $key_196c = { 4e 1e [2] 7c 3c [2] 7a 09 [2] 54 09 [2] 6b 15 }

  condition:
    any of them
}