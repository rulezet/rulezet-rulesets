rule TTP_XOR_WriteProcessMemory_e524 {
  strings:
    $key_e524 = { b2 56 [2] 80 74 [2] 86 41 [2] a8 41 [2] 97 5d }

  condition:
    any of them
}