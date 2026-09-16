rule TTP_XOR_WriteProcessMemory_c8d7 {
  strings:
    $key_c8d7 = { 9f a5 [2] ad 87 [2] ab b2 [2] 85 b2 [2] ba ae }

  condition:
    any of them
}