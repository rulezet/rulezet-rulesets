rule TTP_XOR_WriteProcessMemory_c186 {
  strings:
    $key_c186 = { 96 f4 [2] a4 d6 [2] a2 e3 [2] 8c e3 [2] b3 ff }

  condition:
    any of them
}