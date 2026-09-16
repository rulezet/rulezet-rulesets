rule TTP_XOR_WriteProcessMemory_406c {
  strings:
    $key_406c = { 17 1e [2] 25 3c [2] 23 09 [2] 0d 09 [2] 32 15 }

  condition:
    any of them
}