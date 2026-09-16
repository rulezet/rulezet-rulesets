rule TTP_XOR_WriteProcessMemory_c747 {
  strings:
    $key_c747 = { 90 35 [2] a2 17 [2] a4 22 [2] 8a 22 [2] b5 3e }

  condition:
    any of them
}