rule TTP_XOR_WriteProcessMemory_9fc0 {
  strings:
    $key_9fc0 = { c8 b2 [2] fa 90 [2] fc a5 [2] d2 a5 [2] ed b9 }

  condition:
    any of them
}