rule TTP_XOR_WriteProcessMemory_d6f4 {
  strings:
    $key_d6f4 = { 81 86 [2] b3 a4 [2] b5 91 [2] 9b 91 [2] a4 8d }

  condition:
    any of them
}