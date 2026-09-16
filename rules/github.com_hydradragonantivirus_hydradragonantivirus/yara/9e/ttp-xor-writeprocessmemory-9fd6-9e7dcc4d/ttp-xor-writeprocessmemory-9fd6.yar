rule TTP_XOR_WriteProcessMemory_9fd6 {
  strings:
    $key_9fd6 = { c8 a4 [2] fa 86 [2] fc b3 [2] d2 b3 [2] ed af }

  condition:
    any of them
}