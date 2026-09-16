rule TTP_XOR_WriteProcessMemory_9fa9 {
  strings:
    $key_9fa9 = { c8 db [2] fa f9 [2] fc cc [2] d2 cc [2] ed d0 }

  condition:
    any of them
}