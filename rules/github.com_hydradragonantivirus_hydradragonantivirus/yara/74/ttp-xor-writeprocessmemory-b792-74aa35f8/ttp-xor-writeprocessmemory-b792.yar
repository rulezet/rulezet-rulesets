rule TTP_XOR_WriteProcessMemory_b792 {
  strings:
    $key_b792 = { e0 e0 [2] d2 c2 [2] d4 f7 [2] fa f7 [2] c5 eb }

  condition:
    any of them
}