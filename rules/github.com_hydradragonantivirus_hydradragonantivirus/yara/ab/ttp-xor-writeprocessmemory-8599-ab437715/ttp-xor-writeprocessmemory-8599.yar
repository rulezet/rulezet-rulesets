rule TTP_XOR_WriteProcessMemory_8599 {
  strings:
    $key_8599 = { d2 eb [2] e0 c9 [2] e6 fc [2] c8 fc [2] f7 e0 }

  condition:
    any of them
}