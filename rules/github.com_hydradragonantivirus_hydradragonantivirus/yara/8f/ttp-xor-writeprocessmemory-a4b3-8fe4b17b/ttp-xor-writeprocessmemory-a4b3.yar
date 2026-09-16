rule TTP_XOR_WriteProcessMemory_a4b3 {
  strings:
    $key_a4b3 = { f3 c1 [2] c1 e3 [2] c7 d6 [2] e9 d6 [2] d6 ca }

  condition:
    any of them
}