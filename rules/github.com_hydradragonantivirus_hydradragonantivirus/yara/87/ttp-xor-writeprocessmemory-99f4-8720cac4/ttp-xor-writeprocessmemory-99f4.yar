rule TTP_XOR_WriteProcessMemory_99f4 {
  strings:
    $key_99f4 = { ce 86 [2] fc a4 [2] fa 91 [2] d4 91 [2] eb 8d }

  condition:
    any of them
}