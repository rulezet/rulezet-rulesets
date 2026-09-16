rule TTP_XOR_WriteProcessMemory_b81f {
  strings:
    $key_b81f = { ef 6d [2] dd 4f [2] db 7a [2] f5 7a [2] ca 66 }

  condition:
    any of them
}