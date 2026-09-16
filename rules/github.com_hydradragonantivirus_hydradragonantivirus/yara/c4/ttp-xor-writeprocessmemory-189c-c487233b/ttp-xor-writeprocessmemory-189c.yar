rule TTP_XOR_WriteProcessMemory_189c {
  strings:
    $key_189c = { 4f ee [2] 7d cc [2] 7b f9 [2] 55 f9 [2] 6a e5 }

  condition:
    any of them
}