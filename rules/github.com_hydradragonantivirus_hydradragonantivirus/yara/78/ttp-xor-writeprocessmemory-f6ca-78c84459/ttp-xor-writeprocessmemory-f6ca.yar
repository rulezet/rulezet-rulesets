rule TTP_XOR_WriteProcessMemory_f6ca {
  strings:
    $key_f6ca = { a1 b8 [2] 93 9a [2] 95 af [2] bb af [2] 84 b3 }

  condition:
    any of them
}