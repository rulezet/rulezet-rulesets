rule TTP_XOR_WriteProcessMemory_c031 {
  strings:
    $key_c031 = { 97 43 [2] a5 61 [2] a3 54 [2] 8d 54 [2] b2 48 }

  condition:
    any of them
}