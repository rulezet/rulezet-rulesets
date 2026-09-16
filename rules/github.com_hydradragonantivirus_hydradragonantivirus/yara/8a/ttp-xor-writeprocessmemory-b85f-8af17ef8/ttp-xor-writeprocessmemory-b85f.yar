rule TTP_XOR_WriteProcessMemory_b85f {
  strings:
    $key_b85f = { ef 2d [2] dd 0f [2] db 3a [2] f5 3a [2] ca 26 }

  condition:
    any of them
}