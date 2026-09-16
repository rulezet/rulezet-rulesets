rule TTP_XOR_WriteProcessMemory_efe6 {
  strings:
    $key_efe6 = { b8 94 [2] 8a b6 [2] 8c 83 [2] a2 83 [2] 9d 9f }

  condition:
    any of them
}