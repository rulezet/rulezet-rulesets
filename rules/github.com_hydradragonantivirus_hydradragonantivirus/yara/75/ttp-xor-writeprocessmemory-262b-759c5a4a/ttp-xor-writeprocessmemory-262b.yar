rule TTP_XOR_WriteProcessMemory_262b {
  strings:
    $key_262b = { 71 59 [2] 43 7b [2] 45 4e [2] 6b 4e [2] 54 52 }

  condition:
    any of them
}