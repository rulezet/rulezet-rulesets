rule TTP_XOR_WriteProcessMemory_f61a {
  strings:
    $key_f61a = { a1 68 [2] 93 4a [2] 95 7f [2] bb 7f [2] 84 63 }

  condition:
    any of them
}