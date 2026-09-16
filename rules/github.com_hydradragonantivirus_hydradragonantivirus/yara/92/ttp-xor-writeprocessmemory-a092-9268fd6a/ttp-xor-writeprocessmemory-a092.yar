rule TTP_XOR_WriteProcessMemory_a092 {
  strings:
    $key_a092 = { f7 e0 [2] c5 c2 [2] c3 f7 [2] ed f7 [2] d2 eb }

  condition:
    any of them
}