rule TTP_XOR_WriteProcessMemory_9fd3 {
  strings:
    $key_9fd3 = { c8 a1 [2] fa 83 [2] fc b6 [2] d2 b6 [2] ed aa }

  condition:
    any of them
}