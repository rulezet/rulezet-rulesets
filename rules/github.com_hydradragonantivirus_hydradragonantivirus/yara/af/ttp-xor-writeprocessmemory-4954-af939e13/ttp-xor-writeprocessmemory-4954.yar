rule TTP_XOR_WriteProcessMemory_4954 {
  strings:
    $key_4954 = { 1e 26 [2] 2c 04 [2] 2a 31 [2] 04 31 [2] 3b 2d }

  condition:
    any of them
}