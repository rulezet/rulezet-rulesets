rule TTP_XOR_WriteProcessMemory_0614 {
  strings:
    $key_0614 = { 51 66 [2] 63 44 [2] 65 71 [2] 4b 71 [2] 74 6d }

  condition:
    any of them
}