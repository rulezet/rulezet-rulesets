rule TTP_XOR_WriteProcessMemory_6614 {
  strings:
    $key_6614 = { 31 66 [2] 03 44 [2] 05 71 [2] 2b 71 [2] 14 6d }

  condition:
    any of them
}