rule TTP_XOR_WriteProcessMemory_f7ca {
  strings:
    $key_f7ca = { a0 b8 [2] 92 9a [2] 94 af [2] ba af [2] 85 b3 }

  condition:
    any of them
}