rule TTP_XOR_WriteProcessMemory_035b {
  strings:
    $key_035b = { 54 29 [2] 66 0b [2] 60 3e [2] 4e 3e [2] 71 22 }

  condition:
    any of them
}