rule TTP_XOR_WriteProcessMemory_b2f9 {
  strings:
    $key_b2f9 = { e5 8b [2] d7 a9 [2] d1 9c [2] ff 9c [2] c0 80 }

  condition:
    any of them
}