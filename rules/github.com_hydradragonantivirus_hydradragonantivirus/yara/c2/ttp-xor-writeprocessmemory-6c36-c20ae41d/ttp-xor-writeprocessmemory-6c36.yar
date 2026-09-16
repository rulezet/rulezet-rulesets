rule TTP_XOR_WriteProcessMemory_6c36 {
  strings:
    $key_6c36 = { 3b 44 [2] 09 66 [2] 0f 53 [2] 21 53 [2] 1e 4f }

  condition:
    any of them
}