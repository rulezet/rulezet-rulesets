rule TTP_XOR_WriteProcessMemory_4614 {
  strings:
    $key_4614 = { 11 66 [2] 23 44 [2] 25 71 [2] 0b 71 [2] 34 6d }

  condition:
    any of them
}