rule TTP_XOR_WriteProcessMemory_e37b {
  strings:
    $key_e37b = { b4 09 [2] 86 2b [2] 80 1e [2] ae 1e [2] 91 02 }

  condition:
    any of them
}