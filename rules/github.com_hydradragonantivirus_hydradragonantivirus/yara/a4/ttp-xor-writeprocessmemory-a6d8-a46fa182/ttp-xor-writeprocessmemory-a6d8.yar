rule TTP_XOR_WriteProcessMemory_a6d8 {
  strings:
    $key_a6d8 = { f1 aa [2] c3 88 [2] c5 bd [2] eb bd [2] d4 a1 }

  condition:
    any of them
}