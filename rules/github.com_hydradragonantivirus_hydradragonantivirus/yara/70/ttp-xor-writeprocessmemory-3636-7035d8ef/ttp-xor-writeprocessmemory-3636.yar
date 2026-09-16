rule TTP_XOR_WriteProcessMemory_3636 {
  strings:
    $key_3636 = { 61 44 [2] 53 66 [2] 55 53 [2] 7b 53 [2] 44 4f }

  condition:
    any of them
}