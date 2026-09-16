rule TTP_XOR_WriteProcessMemory_b2e9 {
  strings:
    $key_b2e9 = { e5 9b [2] d7 b9 [2] d1 8c [2] ff 8c [2] c0 90 }

  condition:
    any of them
}