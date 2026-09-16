rule TTP_XOR_WriteProcessMemory_cd9b {
  strings:
    $key_cd9b = { 9a e9 [2] a8 cb [2] ae fe [2] 80 fe [2] bf e2 }

  condition:
    any of them
}