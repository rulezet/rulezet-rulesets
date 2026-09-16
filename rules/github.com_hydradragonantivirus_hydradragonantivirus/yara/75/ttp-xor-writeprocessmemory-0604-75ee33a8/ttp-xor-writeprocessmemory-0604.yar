rule TTP_XOR_WriteProcessMemory_0604 {
  strings:
    $key_0604 = { 51 76 [2] 63 54 [2] 65 61 [2] 4b 61 [2] 74 7d }

  condition:
    any of them
}