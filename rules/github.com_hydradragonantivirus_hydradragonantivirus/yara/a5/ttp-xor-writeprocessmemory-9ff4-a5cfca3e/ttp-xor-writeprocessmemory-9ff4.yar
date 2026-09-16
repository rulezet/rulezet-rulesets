rule TTP_XOR_WriteProcessMemory_9ff4 {
  strings:
    $key_9ff4 = { c8 86 [2] fa a4 [2] fc 91 [2] d2 91 [2] ed 8d }

  condition:
    any of them
}