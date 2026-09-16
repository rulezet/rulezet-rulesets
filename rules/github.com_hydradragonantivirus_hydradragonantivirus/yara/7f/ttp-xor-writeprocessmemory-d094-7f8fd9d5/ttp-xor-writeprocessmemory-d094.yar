rule TTP_XOR_WriteProcessMemory_d094 {
  strings:
    $key_d094 = { 87 e6 [2] b5 c4 [2] b3 f1 [2] 9d f1 [2] a2 ed }

  condition:
    any of them
}