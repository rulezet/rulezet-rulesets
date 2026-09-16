rule TTP_XOR_WriteProcessMemory_a670 {
  strings:
    $key_a670 = { f1 02 [2] c3 20 [2] c5 15 [2] eb 15 [2] d4 09 }

  condition:
    any of them
}