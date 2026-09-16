rule TTP_XOR_WriteProcessMemory_3911 {
  strings:
    $key_3911 = { 6e 63 [2] 5c 41 [2] 5a 74 [2] 74 74 [2] 4b 68 }

  condition:
    any of them
}