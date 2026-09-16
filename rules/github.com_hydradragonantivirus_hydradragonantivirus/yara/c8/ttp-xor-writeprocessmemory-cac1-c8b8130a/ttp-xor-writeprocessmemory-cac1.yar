rule TTP_XOR_WriteProcessMemory_cac1 {
  strings:
    $key_cac1 = { 9d b3 [2] af 91 [2] a9 a4 [2] 87 a4 [2] b8 b8 }

  condition:
    any of them
}