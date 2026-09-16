rule TTP_XOR_WriteProcessMemory_0674 {
  strings:
    $key_0674 = { 51 06 [2] 63 24 [2] 65 11 [2] 4b 11 [2] 74 0d }

  condition:
    any of them
}