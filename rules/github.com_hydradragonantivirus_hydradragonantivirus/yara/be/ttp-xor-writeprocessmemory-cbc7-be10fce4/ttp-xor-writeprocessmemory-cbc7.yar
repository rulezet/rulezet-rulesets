rule TTP_XOR_WriteProcessMemory_cbc7 {
  strings:
    $key_cbc7 = { 9c b5 [2] ae 97 [2] a8 a2 [2] 86 a2 [2] b9 be }

  condition:
    any of them
}