rule TTP_XOR_WriteProcessMemory_4bc3 {
  strings:
    $key_4bc3 = { 1c b1 [2] 2e 93 [2] 28 a6 [2] 06 a6 [2] 39 ba }

  condition:
    any of them
}