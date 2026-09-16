rule TTP_XOR_WriteProcessMemory_c690 {
  strings:
    $key_c690 = { 91 e2 [2] a3 c0 [2] a5 f5 [2] 8b f5 [2] b4 e9 }

  condition:
    any of them
}