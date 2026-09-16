rule TTP_XOR_WriteProcessMemory_6d36 {
  strings:
    $key_6d36 = { 3a 44 [2] 08 66 [2] 0e 53 [2] 20 53 [2] 1f 4f }

  condition:
    any of them
}