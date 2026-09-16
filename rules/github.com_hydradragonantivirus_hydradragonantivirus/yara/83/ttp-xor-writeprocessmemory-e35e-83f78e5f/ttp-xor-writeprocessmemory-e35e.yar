rule TTP_XOR_WriteProcessMemory_e35e {
  strings:
    $key_e35e = { b4 2c [2] 86 0e [2] 80 3b [2] ae 3b [2] 91 27 }

  condition:
    any of them
}