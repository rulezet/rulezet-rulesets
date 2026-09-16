rule TTP_XOR_WriteProcessMemory_d134 {
  strings:
    $key_d134 = { 86 46 [2] b4 64 [2] b2 51 [2] 9c 51 [2] a3 4d }

  condition:
    any of them
}