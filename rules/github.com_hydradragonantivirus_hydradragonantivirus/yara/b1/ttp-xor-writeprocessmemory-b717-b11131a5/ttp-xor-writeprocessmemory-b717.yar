rule TTP_XOR_WriteProcessMemory_b717 {
  strings:
    $key_b717 = { e0 65 [2] d2 47 [2] d4 72 [2] fa 72 [2] c5 6e }

  condition:
    any of them
}