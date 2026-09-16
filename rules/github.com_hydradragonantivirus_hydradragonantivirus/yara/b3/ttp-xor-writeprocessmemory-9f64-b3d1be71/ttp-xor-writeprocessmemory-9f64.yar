rule TTP_XOR_WriteProcessMemory_9f64 {
  strings:
    $key_9f64 = { c8 16 [2] fa 34 [2] fc 01 [2] d2 01 [2] ed 1d }

  condition:
    any of them
}