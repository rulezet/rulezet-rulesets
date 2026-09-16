rule TTP_XOR_WriteProcessMemory_b5d8 {
  strings:
    $key_b5d8 = { e2 aa [2] d0 88 [2] d6 bd [2] f8 bd [2] c7 a1 }

  condition:
    any of them
}