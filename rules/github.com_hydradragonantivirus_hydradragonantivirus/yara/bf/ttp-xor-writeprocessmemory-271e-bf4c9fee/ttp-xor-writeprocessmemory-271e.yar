rule TTP_XOR_WriteProcessMemory_271e {
  strings:
    $key_271e = { 70 6c [2] 42 4e [2] 44 7b [2] 6a 7b [2] 55 67 }

  condition:
    any of them
}