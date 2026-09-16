rule TTP_XOR_WriteProcessMemory_b192 {
  strings:
    $key_b192 = { e6 e0 [2] d4 c2 [2] d2 f7 [2] fc f7 [2] c3 eb }

  condition:
    any of them
}