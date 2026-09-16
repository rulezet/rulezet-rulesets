rule TTP_XOR_WriteProcessMemory_e5d8 {
  strings:
    $key_e5d8 = { b2 aa [2] 80 88 [2] 86 bd [2] a8 bd [2] 97 a1 }

  condition:
    any of them
}