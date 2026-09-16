rule TTP_XOR_WriteProcessMemory_9f05 {
  strings:
    $key_9f05 = { c8 77 [2] fa 55 [2] fc 60 [2] d2 60 [2] ed 7c }

  condition:
    any of them
}