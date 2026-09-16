rule TTP_XOR_WriteProcessMemory_c411 {
  strings:
    $key_c411 = { 93 63 [2] a1 41 [2] a7 74 [2] 89 74 [2] b6 68 }

  condition:
    any of them
}