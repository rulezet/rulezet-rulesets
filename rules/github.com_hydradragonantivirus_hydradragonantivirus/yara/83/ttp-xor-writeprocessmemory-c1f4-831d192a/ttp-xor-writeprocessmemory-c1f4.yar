rule TTP_XOR_WriteProcessMemory_c1f4 {
  strings:
    $key_c1f4 = { 96 86 [2] a4 a4 [2] a2 91 [2] 8c 91 [2] b3 8d }

  condition:
    any of them
}