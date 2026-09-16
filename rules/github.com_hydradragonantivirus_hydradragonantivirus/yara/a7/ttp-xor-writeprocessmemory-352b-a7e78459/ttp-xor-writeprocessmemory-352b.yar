rule TTP_XOR_WriteProcessMemory_352b {
  strings:
    $key_352b = { 62 59 [2] 50 7b [2] 56 4e [2] 78 4e [2] 47 52 }

  condition:
    any of them
}