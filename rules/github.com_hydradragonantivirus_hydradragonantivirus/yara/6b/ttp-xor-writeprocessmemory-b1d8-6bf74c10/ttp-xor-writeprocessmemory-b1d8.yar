rule TTP_XOR_WriteProcessMemory_b1d8 {
  strings:
    $key_b1d8 = { e6 aa [2] d4 88 [2] d2 bd [2] fc bd [2] c3 a1 }

  condition:
    any of them
}