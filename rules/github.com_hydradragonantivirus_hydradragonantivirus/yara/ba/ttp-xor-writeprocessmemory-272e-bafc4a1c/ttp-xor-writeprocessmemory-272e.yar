rule TTP_XOR_WriteProcessMemory_272e {
  strings:
    $key_272e = { 70 5c [2] 42 7e [2] 44 4b [2] 6a 4b [2] 55 57 }

  condition:
    any of them
}