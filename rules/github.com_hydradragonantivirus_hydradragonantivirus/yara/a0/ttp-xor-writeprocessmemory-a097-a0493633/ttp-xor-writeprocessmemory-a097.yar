rule TTP_XOR_WriteProcessMemory_a097 {
  strings:
    $key_a097 = { f7 e5 [2] c5 c7 [2] c3 f2 [2] ed f2 [2] d2 ee }

  condition:
    any of them
}