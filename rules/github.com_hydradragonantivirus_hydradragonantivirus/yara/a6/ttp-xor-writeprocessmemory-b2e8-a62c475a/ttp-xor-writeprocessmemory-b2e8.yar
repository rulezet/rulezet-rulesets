rule TTP_XOR_WriteProcessMemory_b2e8 {
  strings:
    $key_b2e8 = { e5 9a [2] d7 b8 [2] d1 8d [2] ff 8d [2] c0 91 }

  condition:
    any of them
}