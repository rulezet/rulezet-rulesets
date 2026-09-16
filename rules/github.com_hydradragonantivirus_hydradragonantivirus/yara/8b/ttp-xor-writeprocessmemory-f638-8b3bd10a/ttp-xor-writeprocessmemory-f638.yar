rule TTP_XOR_WriteProcessMemory_f638 {
  strings:
    $key_f638 = { a1 4a [2] 93 68 [2] 95 5d [2] bb 5d [2] 84 41 }

  condition:
    any of them
}