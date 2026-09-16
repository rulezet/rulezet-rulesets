rule TTP_XOR_WriteProcessMemory_2e54 {
  strings:
    $key_2e54 = { 79 26 [2] 4b 04 [2] 4d 31 [2] 63 31 [2] 5c 2d }

  condition:
    any of them
}