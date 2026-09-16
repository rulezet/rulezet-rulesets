rule TTP_XOR_WriteProcessMemory_b3d8 {
  strings:
    $key_b3d8 = { e4 aa [2] d6 88 [2] d0 bd [2] fe bd [2] c1 a1 }

  condition:
    any of them
}