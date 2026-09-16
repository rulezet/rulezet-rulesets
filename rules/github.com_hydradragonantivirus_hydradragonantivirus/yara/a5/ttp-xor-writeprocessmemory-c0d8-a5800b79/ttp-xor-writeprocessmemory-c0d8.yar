rule TTP_XOR_WriteProcessMemory_c0d8 {
  strings:
    $key_c0d8 = { 97 aa [2] a5 88 [2] a3 bd [2] 8d bd [2] b2 a1 }

  condition:
    any of them
}