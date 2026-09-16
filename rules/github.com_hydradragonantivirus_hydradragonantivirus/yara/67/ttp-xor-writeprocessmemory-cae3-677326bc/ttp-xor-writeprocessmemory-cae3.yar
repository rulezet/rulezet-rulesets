rule TTP_XOR_WriteProcessMemory_cae3 {
  strings:
    $key_cae3 = { 9d 91 [2] af b3 [2] a9 86 [2] 87 86 [2] b8 9a }

  condition:
    any of them
}