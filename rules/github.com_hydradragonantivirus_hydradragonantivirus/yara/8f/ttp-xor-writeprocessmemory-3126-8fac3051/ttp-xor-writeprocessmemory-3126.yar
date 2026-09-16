rule TTP_XOR_WriteProcessMemory_3126 {
  strings:
    $key_3126 = { 66 54 [2] 54 76 [2] 52 43 [2] 7c 43 [2] 43 5f }

  condition:
    any of them
}