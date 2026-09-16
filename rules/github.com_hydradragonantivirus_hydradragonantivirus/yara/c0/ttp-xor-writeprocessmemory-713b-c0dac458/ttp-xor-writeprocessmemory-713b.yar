rule TTP_XOR_WriteProcessMemory_713b {
  strings:
    $key_713b = { 26 49 [2] 14 6b [2] 12 5e [2] 3c 5e [2] 03 42 }

  condition:
    any of them
}