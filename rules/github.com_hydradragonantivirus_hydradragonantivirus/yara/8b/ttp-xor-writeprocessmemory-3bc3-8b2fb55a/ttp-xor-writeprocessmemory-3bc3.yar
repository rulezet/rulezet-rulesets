rule TTP_XOR_WriteProcessMemory_3bc3 {
  strings:
    $key_3bc3 = { 6c b1 [2] 5e 93 [2] 58 a6 [2] 76 a6 [2] 49 ba }

  condition:
    any of them
}