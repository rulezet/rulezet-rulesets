rule TTP_XOR_WriteProcessMemory_d1f4 {
  strings:
    $key_d1f4 = { 86 86 [2] b4 a4 [2] b2 91 [2] 9c 91 [2] a3 8d }

  condition:
    any of them
}