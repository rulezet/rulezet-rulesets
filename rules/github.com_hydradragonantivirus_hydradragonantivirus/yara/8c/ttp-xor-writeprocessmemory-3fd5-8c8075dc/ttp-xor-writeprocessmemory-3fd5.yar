rule TTP_XOR_WriteProcessMemory_3fd5 {
  strings:
    $key_3fd5 = { 68 a7 [2] 5a 85 [2] 5c b0 [2] 72 b0 [2] 4d ac }

  condition:
    any of them
}