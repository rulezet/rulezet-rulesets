rule TTP_XOR_WriteProcessMemory_7464 {
  strings:
    $key_7464 = { 23 16 [2] 11 34 [2] 17 01 [2] 39 01 [2] 06 1d }

  condition:
    any of them
}