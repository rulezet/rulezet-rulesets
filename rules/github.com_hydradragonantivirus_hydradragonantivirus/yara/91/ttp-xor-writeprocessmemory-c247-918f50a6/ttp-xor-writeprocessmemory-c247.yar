rule TTP_XOR_WriteProcessMemory_c247 {
  strings:
    $key_c247 = { 95 35 [2] a7 17 [2] a1 22 [2] 8f 22 [2] b0 3e }

  condition:
    any of them
}