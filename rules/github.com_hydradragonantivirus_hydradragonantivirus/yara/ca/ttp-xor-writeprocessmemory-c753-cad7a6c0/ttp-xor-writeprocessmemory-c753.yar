rule TTP_XOR_WriteProcessMemory_c753 {
  strings:
    $key_c753 = { 90 21 [2] a2 03 [2] a4 36 [2] 8a 36 [2] b5 2a }

  condition:
    any of them
}