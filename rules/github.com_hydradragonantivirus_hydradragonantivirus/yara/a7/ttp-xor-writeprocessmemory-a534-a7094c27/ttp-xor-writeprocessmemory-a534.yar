rule TTP_XOR_WriteProcessMemory_a534 {
  strings:
    $key_a534 = { f2 46 [2] c0 64 [2] c6 51 [2] e8 51 [2] d7 4d }

  condition:
    any of them
}