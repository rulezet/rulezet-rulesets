rule TTP_XOR_WriteProcessMemory_ed7f {
  strings:
    $key_ed7f = { ba 0d [2] 88 2f [2] 8e 1a [2] a0 1a [2] 9f 06 }

  condition:
    any of them
}