rule TTP_XOR_WriteProcessMemory_b8ce {
  strings:
    $key_b8ce = { ef bc [2] dd 9e [2] db ab [2] f5 ab [2] ca b7 }

  condition:
    any of them
}