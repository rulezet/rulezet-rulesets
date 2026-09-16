rule TTP_XOR_WriteProcessMemory_b86d {
  strings:
    $key_b86d = { ef 1f [2] dd 3d [2] db 08 [2] f5 08 [2] ca 14 }

  condition:
    any of them
}