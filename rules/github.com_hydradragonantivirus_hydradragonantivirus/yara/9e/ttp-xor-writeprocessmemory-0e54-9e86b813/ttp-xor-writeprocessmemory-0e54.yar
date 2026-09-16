rule TTP_XOR_WriteProcessMemory_0e54 {
  strings:
    $key_0e54 = { 59 26 [2] 6b 04 [2] 6d 31 [2] 43 31 [2] 7c 2d }

  condition:
    any of them
}