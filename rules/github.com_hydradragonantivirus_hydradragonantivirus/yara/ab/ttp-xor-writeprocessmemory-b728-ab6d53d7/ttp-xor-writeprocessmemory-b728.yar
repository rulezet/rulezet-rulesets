rule TTP_XOR_WriteProcessMemory_b728 {
  strings:
    $key_b728 = { e0 5a [2] d2 78 [2] d4 4d [2] fa 4d [2] c5 51 }

  condition:
    any of them
}