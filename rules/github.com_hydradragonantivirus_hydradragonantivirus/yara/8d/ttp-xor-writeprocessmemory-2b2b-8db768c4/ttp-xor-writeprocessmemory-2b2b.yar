rule TTP_XOR_WriteProcessMemory_2b2b {
  strings:
    $key_2b2b = { 7c 59 [2] 4e 7b [2] 48 4e [2] 66 4e [2] 59 52 }

  condition:
    any of them
}