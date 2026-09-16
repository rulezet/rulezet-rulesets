rule TTP_XOR_WriteProcessMemory_68dd {
  strings:
    $key_68dd = { 3f af [2] 0d 8d [2] 0b b8 [2] 25 b8 [2] 1a a4 }

  condition:
    any of them
}