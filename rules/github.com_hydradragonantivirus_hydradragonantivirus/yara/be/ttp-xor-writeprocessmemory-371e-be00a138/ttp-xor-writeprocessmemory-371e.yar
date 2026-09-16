rule TTP_XOR_WriteProcessMemory_371e {
  strings:
    $key_371e = { 60 6c [2] 52 4e [2] 54 7b [2] 7a 7b [2] 45 67 }

  condition:
    any of them
}