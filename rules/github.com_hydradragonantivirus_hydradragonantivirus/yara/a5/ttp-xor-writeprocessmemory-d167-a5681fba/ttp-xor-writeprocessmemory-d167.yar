rule TTP_XOR_WriteProcessMemory_d167 {
  strings:
    $key_d167 = { 86 15 [2] b4 37 [2] b2 02 [2] 9c 02 [2] a3 1e }

  condition:
    any of them
}