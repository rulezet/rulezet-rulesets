rule TTP_XOR_WriteProcessMemory_9fa8 {
  strings:
    $key_9fa8 = { c8 da [2] fa f8 [2] fc cd [2] d2 cd [2] ed d1 }

  condition:
    any of them
}