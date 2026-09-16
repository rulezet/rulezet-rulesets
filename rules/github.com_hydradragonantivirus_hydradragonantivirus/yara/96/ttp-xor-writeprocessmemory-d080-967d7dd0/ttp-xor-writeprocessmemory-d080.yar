rule TTP_XOR_WriteProcessMemory_d080 {
  strings:
    $key_d080 = { 87 f2 [2] b5 d0 [2] b3 e5 [2] 9d e5 [2] a2 f9 }

  condition:
    any of them
}