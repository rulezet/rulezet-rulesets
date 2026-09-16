rule TTP_XOR_WriteProcessMemory_a411 {
  strings:
    $key_a411 = { f3 63 [2] c1 41 [2] c7 74 [2] e9 74 [2] d6 68 }

  condition:
    any of them
}