rule TTP_XOR_WriteProcessMemory_312b {
  strings:
    $key_312b = { 66 59 [2] 54 7b [2] 52 4e [2] 7c 4e [2] 43 52 }

  condition:
    any of them
}