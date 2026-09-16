rule TTP_XOR_WriteProcessMemory_b208 {
  strings:
    $key_b208 = { e5 7a [2] d7 58 [2] d1 6d [2] ff 6d [2] c0 71 }

  condition:
    any of them
}