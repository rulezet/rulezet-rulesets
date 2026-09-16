rule TTP_XOR_WriteProcessMemory_eff1 {
  strings:
    $key_eff1 = { b8 83 [2] 8a a1 [2] 8c 94 [2] a2 94 [2] 9d 88 }

  condition:
    any of them
}