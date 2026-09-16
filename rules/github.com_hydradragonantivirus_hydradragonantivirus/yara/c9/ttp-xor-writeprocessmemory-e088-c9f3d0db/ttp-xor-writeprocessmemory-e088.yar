rule TTP_XOR_WriteProcessMemory_e088 {
  strings:
    $key_e088 = { b7 fa [2] 85 d8 [2] 83 ed [2] ad ed [2] 92 f1 }

  condition:
    any of them
}