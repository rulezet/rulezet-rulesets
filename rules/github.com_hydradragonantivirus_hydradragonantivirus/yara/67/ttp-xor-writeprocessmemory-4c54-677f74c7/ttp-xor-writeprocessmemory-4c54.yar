rule TTP_XOR_WriteProcessMemory_4c54 {
  strings:
    $key_4c54 = { 1b 26 [2] 29 04 [2] 2f 31 [2] 01 31 [2] 3e 2d }

  condition:
    any of them
}