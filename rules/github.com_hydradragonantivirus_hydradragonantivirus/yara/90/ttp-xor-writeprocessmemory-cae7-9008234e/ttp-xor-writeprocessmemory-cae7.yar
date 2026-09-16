rule TTP_XOR_WriteProcessMemory_cae7 {
  strings:
    $key_cae7 = { 9d 95 [2] af b7 [2] a9 82 [2] 87 82 [2] b8 9e }

  condition:
    any of them
}