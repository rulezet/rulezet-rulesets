rule TTP_XOR_WriteProcessMemory_8ece {
  strings:
    $key_8ece = { d9 bc [2] eb 9e [2] ed ab [2] c3 ab [2] fc b7 }

  condition:
    any of them
}