rule TTP_XOR_WriteProcessMemory_f601 {
  strings:
    $key_f601 = { a1 73 [2] 93 51 [2] 95 64 [2] bb 64 [2] 84 78 }

  condition:
    any of them
}