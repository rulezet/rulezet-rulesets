rule TTP_XOR_WriteProcessMemory_5d36 {
  strings:
    $key_5d36 = { 0a 44 [2] 38 66 [2] 3e 53 [2] 10 53 [2] 2f 4f }

  condition:
    any of them
}