rule TTP_XOR_WriteProcessMemory_d117 {
  strings:
    $key_d117 = { 86 65 [2] b4 47 [2] b2 72 [2] 9c 72 [2] a3 6e }

  condition:
    any of them
}