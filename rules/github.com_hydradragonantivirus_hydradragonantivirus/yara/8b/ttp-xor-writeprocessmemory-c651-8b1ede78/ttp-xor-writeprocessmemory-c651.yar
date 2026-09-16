rule TTP_XOR_WriteProcessMemory_c651 {
  strings:
    $key_c651 = { 91 23 [2] a3 01 [2] a5 34 [2] 8b 34 [2] b4 28 }

  condition:
    any of them
}