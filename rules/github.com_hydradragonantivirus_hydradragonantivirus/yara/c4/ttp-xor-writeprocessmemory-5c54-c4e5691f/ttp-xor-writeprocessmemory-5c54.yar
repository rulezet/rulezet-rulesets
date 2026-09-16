rule TTP_XOR_WriteProcessMemory_5c54 {
  strings:
    $key_5c54 = { 0b 26 [2] 39 04 [2] 3f 31 [2] 11 31 [2] 2e 2d }

  condition:
    any of them
}