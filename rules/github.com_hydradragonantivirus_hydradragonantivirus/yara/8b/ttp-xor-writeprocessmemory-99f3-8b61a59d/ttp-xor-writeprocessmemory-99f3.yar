rule TTP_XOR_WriteProcessMemory_99f3 {
  strings:
    $key_99f3 = { ce 81 [2] fc a3 [2] fa 96 [2] d4 96 [2] eb 8a }

  condition:
    any of them
}