rule TTP_XOR_WriteProcessMemory_1114 {
  strings:
    $key_1114 = { 46 66 [2] 74 44 [2] 72 71 [2] 5c 71 [2] 63 6d }

  condition:
    any of them
}