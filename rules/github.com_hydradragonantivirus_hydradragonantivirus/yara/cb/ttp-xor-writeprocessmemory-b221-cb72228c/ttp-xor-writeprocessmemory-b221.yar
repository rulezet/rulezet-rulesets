rule TTP_XOR_WriteProcessMemory_b221 {
  strings:
    $key_b221 = { e5 53 [2] d7 71 [2] d1 44 [2] ff 44 [2] c0 58 }

  condition:
    any of them
}