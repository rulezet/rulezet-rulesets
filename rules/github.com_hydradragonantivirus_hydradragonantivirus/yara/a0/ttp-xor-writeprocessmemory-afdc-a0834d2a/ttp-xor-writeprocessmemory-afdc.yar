rule TTP_XOR_WriteProcessMemory_afdc {
  strings:
    $key_afdc = { f8 ae [2] ca 8c [2] cc b9 [2] e2 b9 [2] dd a5 }

  condition:
    any of them
}