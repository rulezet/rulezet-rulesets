rule TTP_XOR_WriteProcessMemory_ecd9 {
  strings:
    $key_ecd9 = { bb ab [2] 89 89 [2] 8f bc [2] a1 bc [2] 9e a0 }

  condition:
    any of them
}