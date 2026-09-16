rule TTP_XOR_WriteProcessMemory_3bc4 {
  strings:
    $key_3bc4 = { 6c b6 [2] 5e 94 [2] 58 a1 [2] 76 a1 [2] 49 bd }

  condition:
    any of them
}