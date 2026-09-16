rule TTP_XOR_WriteProcessMemory_eca5 {
  strings:
    $key_eca5 = { bb d7 [2] 89 f5 [2] 8f c0 [2] a1 c0 [2] 9e dc }

  condition:
    any of them
}