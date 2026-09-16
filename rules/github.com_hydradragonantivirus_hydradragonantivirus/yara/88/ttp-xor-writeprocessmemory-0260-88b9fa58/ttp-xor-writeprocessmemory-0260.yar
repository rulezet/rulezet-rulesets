rule TTP_XOR_WriteProcessMemory_0260 {
  strings:
    $key_0260 = { 55 12 [2] 67 30 [2] 61 05 [2] 4f 05 [2] 70 19 }

  condition:
    any of them
}