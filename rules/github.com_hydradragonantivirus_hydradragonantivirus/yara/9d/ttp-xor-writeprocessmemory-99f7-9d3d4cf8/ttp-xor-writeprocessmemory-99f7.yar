rule TTP_XOR_WriteProcessMemory_99f7 {
  strings:
    $key_99f7 = { ce 85 [2] fc a7 [2] fa 92 [2] d4 92 [2] eb 8e }

  condition:
    any of them
}