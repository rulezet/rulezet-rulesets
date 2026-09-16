rule TTP_XOR_WriteProcessMemory_c010 {
  strings:
    $key_c010 = { 97 62 [2] a5 40 [2] a3 75 [2] 8d 75 [2] b2 69 }

  condition:
    any of them
}