rule TTP_XOR_WriteProcessMemory_cbc6 {
  strings:
    $key_cbc6 = { 9c b4 [2] ae 96 [2] a8 a3 [2] 86 a3 [2] b9 bf }

  condition:
    any of them
}