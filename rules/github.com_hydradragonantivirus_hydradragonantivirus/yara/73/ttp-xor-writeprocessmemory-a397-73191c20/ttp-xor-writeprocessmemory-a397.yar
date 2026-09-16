rule TTP_XOR_WriteProcessMemory_a397 {
  strings:
    $key_a397 = { f4 e5 [2] c6 c7 [2] c0 f2 [2] ee f2 [2] d1 ee }

  condition:
    any of them
}