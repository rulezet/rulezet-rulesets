rule TTP_XOR_WriteProcessMemory_762b {
  strings:
    $key_762b = { 21 59 [2] 13 7b [2] 15 4e [2] 3b 4e [2] 04 52 }

  condition:
    any of them
}