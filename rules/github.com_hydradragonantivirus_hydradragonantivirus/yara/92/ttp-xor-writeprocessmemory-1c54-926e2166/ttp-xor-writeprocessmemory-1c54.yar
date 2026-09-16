rule TTP_XOR_WriteProcessMemory_1c54 {
  strings:
    $key_1c54 = { 4b 26 [2] 79 04 [2] 7f 31 [2] 51 31 [2] 6e 2d }

  condition:
    any of them
}