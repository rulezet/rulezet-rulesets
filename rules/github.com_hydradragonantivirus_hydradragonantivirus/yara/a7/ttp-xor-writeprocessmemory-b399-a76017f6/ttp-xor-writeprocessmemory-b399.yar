rule TTP_XOR_WriteProcessMemory_b399 {
  strings:
    $key_b399 = { e4 eb [2] d6 c9 [2] d0 fc [2] fe fc [2] c1 e0 }

  condition:
    any of them
}