rule TTP_XOR_WriteProcessMemory_e30b {
  strings:
    $key_e30b = { b4 79 [2] 86 5b [2] 80 6e [2] ae 6e [2] 91 72 }

  condition:
    any of them
}