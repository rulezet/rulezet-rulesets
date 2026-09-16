rule TTP_XOR_WriteProcessMemory_ef36 {
  strings:
    $key_ef36 = { b8 44 [2] 8a 66 [2] 8c 53 [2] a2 53 [2] 9d 4f }

  condition:
    any of them
}