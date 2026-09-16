rule TTP_XOR_WriteProcessMemory_a653 {
  strings:
    $key_a653 = { f1 21 [2] c3 03 [2] c5 36 [2] eb 36 [2] d4 2a }

  condition:
    any of them
}