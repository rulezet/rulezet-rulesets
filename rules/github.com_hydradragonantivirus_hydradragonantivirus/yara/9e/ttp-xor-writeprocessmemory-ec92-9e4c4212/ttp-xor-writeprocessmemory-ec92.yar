rule TTP_XOR_WriteProcessMemory_ec92 {
  strings:
    $key_ec92 = { bb e0 [2] 89 c2 [2] 8f f7 [2] a1 f7 [2] 9e eb }

  condition:
    any of them
}