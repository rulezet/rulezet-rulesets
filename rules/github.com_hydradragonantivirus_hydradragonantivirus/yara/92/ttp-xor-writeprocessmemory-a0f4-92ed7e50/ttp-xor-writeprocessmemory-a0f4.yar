rule TTP_XOR_WriteProcessMemory_a0f4 {
  strings:
    $key_a0f4 = { f7 86 [2] c5 a4 [2] c3 91 [2] ed 91 [2] d2 8d }

  condition:
    any of them
}