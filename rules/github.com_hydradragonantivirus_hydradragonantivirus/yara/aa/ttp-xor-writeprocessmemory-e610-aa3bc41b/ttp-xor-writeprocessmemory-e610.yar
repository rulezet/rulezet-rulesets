rule TTP_XOR_WriteProcessMemory_e610 {
  strings:
    $key_e610 = { b1 62 [2] 83 40 [2] 85 75 [2] ab 75 [2] 94 69 }

  condition:
    any of them
}