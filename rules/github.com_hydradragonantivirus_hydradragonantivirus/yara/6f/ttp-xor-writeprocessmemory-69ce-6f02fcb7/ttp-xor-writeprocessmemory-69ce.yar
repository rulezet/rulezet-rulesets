rule TTP_XOR_WriteProcessMemory_69ce {
  strings:
    $key_69ce = { 3e bc [2] 0c 9e [2] 0a ab [2] 24 ab [2] 1b b7 }

  condition:
    any of them
}