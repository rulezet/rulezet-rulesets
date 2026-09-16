rule TTP_XOR_WriteProcessMemory_5a3e {
  strings:
    $key_5a3e = { 0d 4c [2] 3f 6e [2] 39 5b [2] 17 5b [2] 28 47 }

  condition:
    any of them
}