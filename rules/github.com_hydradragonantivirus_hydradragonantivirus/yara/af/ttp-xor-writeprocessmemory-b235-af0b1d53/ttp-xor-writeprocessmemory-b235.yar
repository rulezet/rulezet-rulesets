rule TTP_XOR_WriteProcessMemory_b235 {
  strings:
    $key_b235 = { e5 47 [2] d7 65 [2] d1 50 [2] ff 50 [2] c0 4c }

  condition:
    any of them
}