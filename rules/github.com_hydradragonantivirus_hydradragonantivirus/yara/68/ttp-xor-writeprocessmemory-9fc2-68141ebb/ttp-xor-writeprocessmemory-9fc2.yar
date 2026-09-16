rule TTP_XOR_WriteProcessMemory_9fc2 {
  strings:
    $key_9fc2 = { c8 b0 [2] fa 92 [2] fc a7 [2] d2 a7 [2] ed bb }

  condition:
    any of them
}