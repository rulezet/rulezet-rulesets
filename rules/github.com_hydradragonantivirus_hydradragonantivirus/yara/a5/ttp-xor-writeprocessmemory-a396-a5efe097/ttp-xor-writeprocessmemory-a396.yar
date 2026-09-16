rule TTP_XOR_WriteProcessMemory_a396 {
  strings:
    $key_a396 = { f4 e4 [2] c6 c6 [2] c0 f3 [2] ee f3 [2] d1 ef }

  condition:
    any of them
}