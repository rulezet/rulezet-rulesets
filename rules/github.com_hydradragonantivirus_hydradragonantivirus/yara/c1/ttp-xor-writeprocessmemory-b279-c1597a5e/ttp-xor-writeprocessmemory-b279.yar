rule TTP_XOR_WriteProcessMemory_b279 {
  strings:
    $key_b279 = { e5 0b [2] d7 29 [2] d1 1c [2] ff 1c [2] c0 00 }

  condition:
    any of them
}