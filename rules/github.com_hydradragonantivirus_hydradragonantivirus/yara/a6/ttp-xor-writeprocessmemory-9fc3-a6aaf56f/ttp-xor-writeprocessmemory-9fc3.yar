rule TTP_XOR_WriteProcessMemory_9fc3 {
  strings:
    $key_9fc3 = { c8 b1 [2] fa 93 [2] fc a6 [2] d2 a6 [2] ed ba }

  condition:
    any of them
}