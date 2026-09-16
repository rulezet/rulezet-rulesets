rule TTP_XOR_WriteProcessMemory_cae1 {
  strings:
    $key_cae1 = { 9d 93 [2] af b1 [2] a9 84 [2] 87 84 [2] b8 98 }

  condition:
    any of them
}