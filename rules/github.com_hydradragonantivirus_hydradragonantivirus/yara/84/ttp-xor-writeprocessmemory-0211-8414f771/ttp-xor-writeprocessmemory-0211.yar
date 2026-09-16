rule TTP_XOR_WriteProcessMemory_0211 {
  strings:
    $key_0211 = { 55 63 [2] 67 41 [2] 61 74 [2] 4f 74 [2] 70 68 }

  condition:
    any of them
}