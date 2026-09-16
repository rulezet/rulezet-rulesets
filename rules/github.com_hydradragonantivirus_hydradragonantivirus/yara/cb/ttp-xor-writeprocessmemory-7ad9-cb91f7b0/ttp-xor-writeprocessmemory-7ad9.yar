rule TTP_XOR_WriteProcessMemory_7ad9 {
  strings:
    $key_7ad9 = { 2d ab [2] 1f 89 [2] 19 bc [2] 37 bc [2] 08 a0 }

  condition:
    any of them
}