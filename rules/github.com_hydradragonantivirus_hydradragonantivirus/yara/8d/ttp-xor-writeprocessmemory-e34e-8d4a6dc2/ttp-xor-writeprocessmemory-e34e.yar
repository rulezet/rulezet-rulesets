rule TTP_XOR_WriteProcessMemory_e34e {
  strings:
    $key_e34e = { b4 3c [2] 86 1e [2] 80 2b [2] ae 2b [2] 91 37 }

  condition:
    any of them
}