rule TTP_XOR_WriteProcessMemory_9991 {
  strings:
    $key_9991 = { ce e3 [2] fc c1 [2] fa f4 [2] d4 f4 [2] eb e8 }

  condition:
    any of them
}