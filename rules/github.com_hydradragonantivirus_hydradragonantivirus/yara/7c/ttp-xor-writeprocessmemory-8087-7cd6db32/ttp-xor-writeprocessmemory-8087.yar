rule TTP_XOR_WriteProcessMemory_8087 {
  strings:
    $key_8087 = { d7 f5 [2] e5 d7 [2] e3 e2 [2] cd e2 [2] f2 fe }

  condition:
    any of them
}