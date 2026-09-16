rule TTP_XOR_WriteProcessMemory_9ff5 {
  strings:
    $key_9ff5 = { c8 87 [2] fa a5 [2] fc 90 [2] d2 90 [2] ed 8c }

  condition:
    any of them
}