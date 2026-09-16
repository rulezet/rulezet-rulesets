rule TTP_XOR_WriteProcessMemory_a599 {
  strings:
    $key_a599 = { f2 eb [2] c0 c9 [2] c6 fc [2] e8 fc [2] d7 e0 }

  condition:
    any of them
}