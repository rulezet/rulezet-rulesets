rule TTP_XOR_WriteProcessMemory_d7b5 {
  strings:
    $key_d7b5 = { 80 c7 [2] b2 e5 [2] b4 d0 [2] 9a d0 [2] a5 cc }

  condition:
    any of them
}