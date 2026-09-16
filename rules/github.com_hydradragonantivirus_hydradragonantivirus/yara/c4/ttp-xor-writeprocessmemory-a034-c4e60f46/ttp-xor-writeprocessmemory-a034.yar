rule TTP_XOR_WriteProcessMemory_a034 {
  strings:
    $key_a034 = { f7 46 [2] c5 64 [2] c3 51 [2] ed 51 [2] d2 4d }

  condition:
    any of them
}