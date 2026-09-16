rule TTP_XOR_WriteProcessMemory_a073 {
  strings:
    $key_a073 = { f7 01 [2] c5 23 [2] c3 16 [2] ed 16 [2] d2 0a }

  condition:
    any of them
}