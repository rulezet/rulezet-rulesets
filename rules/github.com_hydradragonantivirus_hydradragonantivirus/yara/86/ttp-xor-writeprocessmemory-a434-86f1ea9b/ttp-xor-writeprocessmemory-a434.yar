rule TTP_XOR_WriteProcessMemory_a434 {
  strings:
    $key_a434 = { f3 46 [2] c1 64 [2] c7 51 [2] e9 51 [2] d6 4d }

  condition:
    any of them
}