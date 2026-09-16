rule TTP_XOR_WriteProcessMemory_6bc3 {
  strings:
    $key_6bc3 = { 3c b1 [2] 0e 93 [2] 08 a6 [2] 26 a6 [2] 19 ba }

  condition:
    any of them
}