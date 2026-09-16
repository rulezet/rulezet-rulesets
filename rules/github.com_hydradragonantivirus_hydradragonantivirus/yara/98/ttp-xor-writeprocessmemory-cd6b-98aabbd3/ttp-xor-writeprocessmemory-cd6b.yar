rule TTP_XOR_WriteProcessMemory_cd6b {
  strings:
    $key_cd6b = { 9a 19 [2] a8 3b [2] ae 0e [2] 80 0e [2] bf 12 }

  condition:
    any of them
}