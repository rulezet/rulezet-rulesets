rule TTP_XOR_WriteProcessMemory_0c54 {
  strings:
    $key_0c54 = { 5b 26 [2] 69 04 [2] 6f 31 [2] 41 31 [2] 7e 2d }

  condition:
    any of them
}