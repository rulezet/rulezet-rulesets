rule TTP_XOR_WriteProcessMemory_723b {
  strings:
    $key_723b = { 25 49 [2] 17 6b [2] 11 5e [2] 3f 5e [2] 00 42 }

  condition:
    any of them
}