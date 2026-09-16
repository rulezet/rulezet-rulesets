rule TTP_XOR_WriteProcessMemory_cd5b {
  strings:
    $key_cd5b = { 9a 29 [2] a8 0b [2] ae 3e [2] 80 3e [2] bf 22 }

  condition:
    any of them
}