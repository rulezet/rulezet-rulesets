rule TTP_XOR_WriteProcessMemory_8199 {
  strings:
    $key_8199 = { d6 eb [2] e4 c9 [2] e2 fc [2] cc fc [2] f3 e0 }

  condition:
    any of them
}