rule TTP_XOR_WriteProcessMemory_0311 {
  strings:
    $key_0311 = { 54 63 [2] 66 41 [2] 60 74 [2] 4e 74 [2] 71 68 }

  condition:
    any of them
}