rule TTP_XOR_WriteProcessMemory_7217 {
  strings:
    $key_7217 = { 25 65 [2] 17 47 [2] 11 72 [2] 3f 72 [2] 00 6e }

  condition:
    any of them
}