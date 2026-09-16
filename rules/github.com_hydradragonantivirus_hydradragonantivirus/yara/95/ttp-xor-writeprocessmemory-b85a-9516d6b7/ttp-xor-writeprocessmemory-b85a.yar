rule TTP_XOR_WriteProcessMemory_b85a {
  strings:
    $key_b85a = { ef 28 [2] dd 0a [2] db 3f [2] f5 3f [2] ca 23 }

  condition:
    any of them
}