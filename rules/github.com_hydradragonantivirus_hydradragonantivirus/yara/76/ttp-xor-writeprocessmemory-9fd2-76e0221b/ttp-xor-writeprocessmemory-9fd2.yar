rule TTP_XOR_WriteProcessMemory_9fd2 {
  strings:
    $key_9fd2 = { c8 a0 [2] fa 82 [2] fc b7 [2] d2 b7 [2] ed ab }

  condition:
    any of them
}