rule TTP_XOR_WriteProcessMemory_b297 {
  strings:
    $key_b297 = { e5 e5 [2] d7 c7 [2] d1 f2 [2] ff f2 [2] c0 ee }

  condition:
    any of them
}