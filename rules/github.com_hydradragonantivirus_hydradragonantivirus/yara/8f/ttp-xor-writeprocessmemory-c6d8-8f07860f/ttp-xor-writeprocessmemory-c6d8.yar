rule TTP_XOR_WriteProcessMemory_c6d8 {
  strings:
    $key_c6d8 = { 91 aa [2] a3 88 [2] a5 bd [2] 8b bd [2] b4 a1 }

  condition:
    any of them
}