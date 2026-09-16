rule TTP_XOR_WriteProcessMemory_b423 {
  strings:
    $key_b423 = { e3 51 [2] d1 73 [2] d7 46 [2] f9 46 [2] c6 5a }

  condition:
    any of them
}