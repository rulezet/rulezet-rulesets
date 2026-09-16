rule TTP_XOR_WriteProcessMemory_344e {
  strings:
    $key_344e = { 63 3c [2] 51 1e [2] 57 2b [2] 79 2b [2] 46 37 }

  condition:
    any of them
}