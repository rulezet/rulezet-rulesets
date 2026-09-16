rule TTP_XOR_WriteProcessMemory_291e {
  strings:
    $key_291e = { 7e 6c [2] 4c 4e [2] 4a 7b [2] 64 7b [2] 5b 67 }

  condition:
    any of them
}