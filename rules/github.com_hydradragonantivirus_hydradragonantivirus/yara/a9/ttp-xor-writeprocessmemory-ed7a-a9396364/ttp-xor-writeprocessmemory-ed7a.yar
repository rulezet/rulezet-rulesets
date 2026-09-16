rule TTP_XOR_WriteProcessMemory_ed7a {
  strings:
    $key_ed7a = { ba 08 [2] 88 2a [2] 8e 1f [2] a0 1f [2] 9f 03 }

  condition:
    any of them
}