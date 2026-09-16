rule TTP_XOR_WriteProcessMemory_9fd1 {
  strings:
    $key_9fd1 = { c8 a3 [2] fa 81 [2] fc b4 [2] d2 b4 [2] ed a8 }

  condition:
    any of them
}