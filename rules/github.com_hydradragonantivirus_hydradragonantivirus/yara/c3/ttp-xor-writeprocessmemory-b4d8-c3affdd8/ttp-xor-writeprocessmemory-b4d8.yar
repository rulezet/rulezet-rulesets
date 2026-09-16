rule TTP_XOR_WriteProcessMemory_b4d8 {
  strings:
    $key_b4d8 = { e3 aa [2] d1 88 [2] d7 bd [2] f9 bd [2] c6 a1 }

  condition:
    any of them
}