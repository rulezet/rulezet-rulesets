rule TTP_XOR_WriteProcessMemory_a523 {
  strings:
    $key_a523 = { f2 51 [2] c0 73 [2] c6 46 [2] e8 46 [2] d7 5a }

  condition:
    any of them
}