rule TTP_XOR_WriteProcessMemory_e7e3 {
  strings:
    $key_e7e3 = { b0 91 [2] 82 b3 [2] 84 86 [2] aa 86 [2] 95 9a }

  condition:
    any of them
}