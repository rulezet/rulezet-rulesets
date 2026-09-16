rule TTP_XOR_WriteProcessMemory_99f1 {
  strings:
    $key_99f1 = { ce 83 [2] fc a1 [2] fa 94 [2] d4 94 [2] eb 88 }

  condition:
    any of them
}