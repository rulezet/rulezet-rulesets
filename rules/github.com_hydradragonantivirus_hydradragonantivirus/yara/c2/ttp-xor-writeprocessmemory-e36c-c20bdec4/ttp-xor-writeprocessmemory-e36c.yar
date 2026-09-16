rule TTP_XOR_WriteProcessMemory_e36c {
  strings:
    $key_e36c = { b4 1e [2] 86 3c [2] 80 09 [2] ae 09 [2] 91 15 }

  condition:
    any of them
}