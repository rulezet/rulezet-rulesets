rule TTP_XOR_WriteProcessMemory_b599 {
  strings:
    $key_b599 = { e2 eb [2] d0 c9 [2] d6 fc [2] f8 fc [2] c7 e0 }

  condition:
    any of them
}