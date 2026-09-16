rule TTP_XOR_WriteProcessMemory_242b {
  strings:
    $key_242b = { 73 59 [2] 41 7b [2] 47 4e [2] 69 4e [2] 56 52 }

  condition:
    any of them
}