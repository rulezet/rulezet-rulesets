rule TTP_XOR_WriteProcessMemory_b83f {
  strings:
    $key_b83f = { ef 4d [2] dd 6f [2] db 5a [2] f5 5a [2] ca 46 }

  condition:
    any of them
}