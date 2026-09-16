rule TTP_XOR_WriteProcessMemory_324c {
  strings:
    $key_324c = { 65 3e [2] 57 1c [2] 51 29 [2] 7f 29 [2] 40 35 }

  condition:
    any of them
}