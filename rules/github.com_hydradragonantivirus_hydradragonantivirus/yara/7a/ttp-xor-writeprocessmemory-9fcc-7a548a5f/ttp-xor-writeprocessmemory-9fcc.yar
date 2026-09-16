rule TTP_XOR_WriteProcessMemory_9fcc {
  strings:
    $key_9fcc = { c8 be [2] fa 9c [2] fc a9 [2] d2 a9 [2] ed b5 }

  condition:
    any of them
}