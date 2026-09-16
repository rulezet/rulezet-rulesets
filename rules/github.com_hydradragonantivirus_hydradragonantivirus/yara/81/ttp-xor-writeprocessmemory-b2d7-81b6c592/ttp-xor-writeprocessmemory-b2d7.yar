rule TTP_XOR_WriteProcessMemory_b2d7 {
  strings:
    $key_b2d7 = { e5 a5 [2] d7 87 [2] d1 b2 [2] ff b2 [2] c0 ae }

  condition:
    any of them
}