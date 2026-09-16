rule TTP_XOR_WriteProcessMemory_452b {
  strings:
    $key_452b = { 12 59 [2] 20 7b [2] 26 4e [2] 08 4e [2] 37 52 }

  condition:
    any of them
}