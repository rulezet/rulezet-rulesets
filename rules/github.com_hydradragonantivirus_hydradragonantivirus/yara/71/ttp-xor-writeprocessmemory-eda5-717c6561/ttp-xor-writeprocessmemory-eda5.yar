rule TTP_XOR_WriteProcessMemory_eda5 {
  strings:
    $key_eda5 = { ba d7 [2] 88 f5 [2] 8e c0 [2] a0 c0 [2] 9f dc }

  condition:
    any of them
}