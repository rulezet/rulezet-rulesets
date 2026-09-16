rule TTP_XOR_WriteProcessMemory_b8ca {
  strings:
    $key_b8ca = { ef b8 [2] dd 9a [2] db af [2] f5 af [2] ca b3 }

  condition:
    any of them
}