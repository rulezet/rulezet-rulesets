rule TTP_XOR_WriteProcessMemory_162b {
  strings:
    $key_162b = { 41 59 [2] 73 7b [2] 75 4e [2] 5b 4e [2] 64 52 }

  condition:
    any of them
}