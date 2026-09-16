rule TTP_XOR_WriteProcessMemory_b8cb {
  strings:
    $key_b8cb = { ef b9 [2] dd 9b [2] db ae [2] f5 ae [2] ca b2 }

  condition:
    any of them
}