rule TTP_XOR_WriteProcessMemory_dce6 {
  strings:
    $key_dce6 = { 8b 94 [2] b9 b6 [2] bf 83 [2] 91 83 [2] ae 9f }

  condition:
    any of them
}