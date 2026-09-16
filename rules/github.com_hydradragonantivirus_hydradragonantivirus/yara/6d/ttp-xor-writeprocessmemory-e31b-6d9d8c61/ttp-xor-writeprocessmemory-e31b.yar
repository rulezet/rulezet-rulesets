rule TTP_XOR_WriteProcessMemory_e31b {
  strings:
    $key_e31b = { b4 69 [2] 86 4b [2] 80 7e [2] ae 7e [2] 91 62 }

  condition:
    any of them
}