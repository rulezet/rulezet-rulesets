rule TTP_XOR_WriteProcessMemory_ca85 {
  strings:
    $key_ca85 = { 9d f7 [2] af d5 [2] a9 e0 [2] 87 e0 [2] b8 fc }

  condition:
    any of them
}