rule TTP_XOR_WriteProcessMemory_b84f {
  strings:
    $key_b84f = { ef 3d [2] dd 1f [2] db 2a [2] f5 2a [2] ca 36 }

  condition:
    any of them
}