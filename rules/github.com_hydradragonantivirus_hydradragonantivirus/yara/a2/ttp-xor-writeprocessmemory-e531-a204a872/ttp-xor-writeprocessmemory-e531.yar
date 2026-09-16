rule TTP_XOR_WriteProcessMemory_e531 {
  strings:
    $key_e531 = { b2 43 [2] 80 61 [2] 86 54 [2] a8 54 [2] 97 48 }

  condition:
    any of them
}