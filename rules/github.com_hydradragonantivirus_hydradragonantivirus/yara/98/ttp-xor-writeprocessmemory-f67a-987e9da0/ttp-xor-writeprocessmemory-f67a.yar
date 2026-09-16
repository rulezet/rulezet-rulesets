rule TTP_XOR_WriteProcessMemory_f67a {
  strings:
    $key_f67a = { a1 08 [2] 93 2a [2] 95 1f [2] bb 1f [2] 84 03 }

  condition:
    any of them
}