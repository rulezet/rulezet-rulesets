rule TTP_XOR_WriteProcessMemory_2164 {
  strings:
    $key_2164 = { 76 16 [2] 44 34 [2] 42 01 [2] 6c 01 [2] 53 1d }

  condition:
    any of them
}