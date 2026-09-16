rule TTP_XOR_WriteProcessMemory_332c {
  strings:
    $key_332c = { 64 5e [2] 56 7c [2] 50 49 [2] 7e 49 [2] 41 55 }

  condition:
    any of them
}