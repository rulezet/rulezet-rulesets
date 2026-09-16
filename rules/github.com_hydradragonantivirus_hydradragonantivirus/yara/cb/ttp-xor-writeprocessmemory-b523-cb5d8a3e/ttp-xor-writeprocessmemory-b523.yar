rule TTP_XOR_WriteProcessMemory_b523 {
  strings:
    $key_b523 = { e2 51 [2] d0 73 [2] d6 46 [2] f8 46 [2] c7 5a }

  condition:
    any of them
}