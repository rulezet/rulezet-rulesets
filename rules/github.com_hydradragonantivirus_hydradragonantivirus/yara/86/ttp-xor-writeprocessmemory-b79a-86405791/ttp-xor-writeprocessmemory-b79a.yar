rule TTP_XOR_WriteProcessMemory_b79a {
  strings:
    $key_b79a = { e0 e8 [2] d2 ca [2] d4 ff [2] fa ff [2] c5 e3 }

  condition:
    any of them
}