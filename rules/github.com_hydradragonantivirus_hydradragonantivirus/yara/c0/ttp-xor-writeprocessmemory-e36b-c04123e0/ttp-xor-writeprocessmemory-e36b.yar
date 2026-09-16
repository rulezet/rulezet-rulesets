rule TTP_XOR_WriteProcessMemory_e36b {
  strings:
    $key_e36b = { b4 19 [2] 86 3b [2] 80 0e [2] ae 0e [2] 91 12 }

  condition:
    any of them
}