rule TTP_XOR_WriteProcessMemory_d186 {
  strings:
    $key_d186 = { 86 f4 [2] b4 d6 [2] b2 e3 [2] 9c e3 [2] a3 ff }

  condition:
    any of them
}