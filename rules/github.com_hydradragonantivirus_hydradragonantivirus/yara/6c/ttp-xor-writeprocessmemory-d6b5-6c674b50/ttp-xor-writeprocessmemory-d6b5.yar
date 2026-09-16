rule TTP_XOR_WriteProcessMemory_d6b5 {
  strings:
    $key_d6b5 = { 81 c7 [2] b3 e5 [2] b5 d0 [2] 9b d0 [2] a4 cc }

  condition:
    any of them
}