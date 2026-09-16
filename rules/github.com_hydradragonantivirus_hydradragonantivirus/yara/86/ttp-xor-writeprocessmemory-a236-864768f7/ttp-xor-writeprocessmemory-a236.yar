rule TTP_XOR_WriteProcessMemory_a236 {
  strings:
    $key_a236 = { f5 44 [2] c7 66 [2] c1 53 [2] ef 53 [2] d0 4f }

  condition:
    any of them
}