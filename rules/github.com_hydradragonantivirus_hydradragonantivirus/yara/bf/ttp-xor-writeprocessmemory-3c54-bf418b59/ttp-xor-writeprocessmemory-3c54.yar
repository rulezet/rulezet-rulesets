rule TTP_XOR_WriteProcessMemory_3c54 {
  strings:
    $key_3c54 = { 6b 26 [2] 59 04 [2] 5f 31 [2] 71 31 [2] 4e 2d }

  condition:
    any of them
}