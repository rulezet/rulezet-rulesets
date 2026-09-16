rule TTP_XOR_WriteProcessMemory_6624 {
  strings:
    $key_6624 = { 31 56 [2] 03 74 [2] 05 41 [2] 2b 41 [2] 14 5d }

  condition:
    any of them
}