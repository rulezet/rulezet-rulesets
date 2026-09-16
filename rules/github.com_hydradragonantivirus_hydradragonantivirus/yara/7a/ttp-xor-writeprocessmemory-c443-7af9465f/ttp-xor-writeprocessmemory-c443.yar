rule TTP_XOR_WriteProcessMemory_c443 {
  strings:
    $key_c443 = { 93 31 [2] a1 13 [2] a7 26 [2] 89 26 [2] b6 3a }

  condition:
    any of them
}