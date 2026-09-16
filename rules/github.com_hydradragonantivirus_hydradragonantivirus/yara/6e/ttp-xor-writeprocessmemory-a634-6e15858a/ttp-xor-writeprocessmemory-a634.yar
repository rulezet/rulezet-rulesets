rule TTP_XOR_WriteProcessMemory_a634 {
  strings:
    $key_a634 = { f1 46 [2] c3 64 [2] c5 51 [2] eb 51 [2] d4 4d }

  condition:
    any of them
}