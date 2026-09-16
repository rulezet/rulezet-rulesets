rule TTP_XOR_WriteProcessMemory_d1d8 {
  strings:
    $key_d1d8 = { 86 aa [2] b4 88 [2] b2 bd [2] 9c bd [2] a3 a1 }

  condition:
    any of them
}