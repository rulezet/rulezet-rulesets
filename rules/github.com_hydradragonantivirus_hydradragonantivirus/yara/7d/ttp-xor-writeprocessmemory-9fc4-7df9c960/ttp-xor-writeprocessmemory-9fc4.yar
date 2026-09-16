rule TTP_XOR_WriteProcessMemory_9fc4 {
  strings:
    $key_9fc4 = { c8 b6 [2] fa 94 [2] fc a1 [2] d2 a1 [2] ed bd }

  condition:
    any of them
}