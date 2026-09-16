rule TTP_XOR_WriteProcessMemory_a071 {
  strings:
    $key_a071 = { f7 03 [2] c5 21 [2] c3 14 [2] ed 14 [2] d2 08 }

  condition:
    any of them
}