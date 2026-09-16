rule TTP_XOR_WriteProcessMemory_cbc3 {
  strings:
    $key_cbc3 = { 9c b1 [2] ae 93 [2] a8 a6 [2] 86 a6 [2] b9 ba }

  condition:
    any of them
}