rule TTP_XOR_WriteProcessMemory_b8cd {
  strings:
    $key_b8cd = { ef bf [2] dd 9d [2] db a8 [2] f5 a8 [2] ca b4 }

  condition:
    any of them
}