rule TTP_XOR_WriteProcessMemory_6c54 {
  strings:
    $key_6c54 = { 3b 26 [2] 09 04 [2] 0f 31 [2] 21 31 [2] 1e 2d }

  condition:
    any of them
}