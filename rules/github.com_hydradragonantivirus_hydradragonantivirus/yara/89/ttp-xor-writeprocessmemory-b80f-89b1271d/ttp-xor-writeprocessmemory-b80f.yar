rule TTP_XOR_WriteProcessMemory_b80f {
  strings:
    $key_b80f = { ef 7d [2] dd 5f [2] db 6a [2] f5 6a [2] ca 76 }

  condition:
    any of them
}