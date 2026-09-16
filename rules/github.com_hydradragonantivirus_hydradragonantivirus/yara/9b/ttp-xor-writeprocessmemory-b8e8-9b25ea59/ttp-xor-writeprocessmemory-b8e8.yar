rule TTP_XOR_WriteProcessMemory_b8e8 {
  strings:
    $key_b8e8 = { ef 9a [2] dd b8 [2] db 8d [2] f5 8d [2] ca 91 }

  condition:
    any of them
}