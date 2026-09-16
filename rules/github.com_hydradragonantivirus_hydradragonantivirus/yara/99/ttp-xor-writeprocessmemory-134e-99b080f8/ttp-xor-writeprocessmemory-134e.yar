rule TTP_XOR_WriteProcessMemory_134e {
  strings:
    $key_134e = { 44 3c [2] 76 1e [2] 70 2b [2] 5e 2b [2] 61 37 }

  condition:
    any of them
}