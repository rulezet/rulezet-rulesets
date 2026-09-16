rule TTP_XOR_WriteProcessMemory_184e {
  strings:
    $key_184e = { 4f 3c [2] 7d 1e [2] 7b 2b [2] 55 2b [2] 6a 37 }

  condition:
    any of them
}