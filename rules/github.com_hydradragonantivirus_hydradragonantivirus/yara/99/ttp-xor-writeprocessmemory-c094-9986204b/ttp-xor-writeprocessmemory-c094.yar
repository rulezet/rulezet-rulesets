rule TTP_XOR_WriteProcessMemory_c094 {
  strings:
    $key_c094 = { 97 e6 [2] a5 c4 [2] a3 f1 [2] 8d f1 [2] b2 ed }

  condition:
    any of them
}