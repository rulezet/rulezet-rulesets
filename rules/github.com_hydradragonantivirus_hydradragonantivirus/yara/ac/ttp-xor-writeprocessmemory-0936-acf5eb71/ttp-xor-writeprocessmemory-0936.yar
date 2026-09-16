rule TTP_XOR_WriteProcessMemory_0936 {
  strings:
    $key_0936 = { 5e 44 [2] 6c 66 [2] 6a 53 [2] 44 53 [2] 7b 4f }

  condition:
    any of them
}