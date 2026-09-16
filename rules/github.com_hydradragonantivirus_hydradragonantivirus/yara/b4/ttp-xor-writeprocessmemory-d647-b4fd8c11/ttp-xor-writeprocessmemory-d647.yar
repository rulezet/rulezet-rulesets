rule TTP_XOR_WriteProcessMemory_d647 {
  strings:
    $key_d647 = { 81 35 [2] b3 17 [2] b5 22 [2] 9b 22 [2] a4 3e }

  condition:
    any of them
}