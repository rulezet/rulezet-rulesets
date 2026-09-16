rule TTP_XOR_WriteProcessMemory_7174 {
  strings:
    $key_7174 = { 26 06 [2] 14 24 [2] 12 11 [2] 3c 11 [2] 03 0d }

  condition:
    any of them
}