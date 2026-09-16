rule TTP_XOR_WriteProcessMemory_283b {
  strings:
    $key_283b = { 7f 49 [2] 4d 6b [2] 4b 5e [2] 65 5e [2] 5a 42 }

  condition:
    any of them
}