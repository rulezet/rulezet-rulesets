rule TTP_XOR_WriteProcessMemory_cae6 {
  strings:
    $key_cae6 = { 9d 94 [2] af b6 [2] a9 83 [2] 87 83 [2] b8 9f }

  condition:
    any of them
}