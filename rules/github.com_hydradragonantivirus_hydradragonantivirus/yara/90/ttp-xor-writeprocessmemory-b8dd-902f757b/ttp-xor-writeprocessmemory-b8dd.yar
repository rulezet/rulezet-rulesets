rule TTP_XOR_WriteProcessMemory_b8dd {
  strings:
    $key_b8dd = { ef af [2] dd 8d [2] db b8 [2] f5 b8 [2] ca a4 }

  condition:
    any of them
}