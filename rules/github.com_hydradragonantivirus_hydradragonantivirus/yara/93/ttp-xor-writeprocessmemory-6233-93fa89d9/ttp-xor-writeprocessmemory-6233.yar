rule TTP_XOR_WriteProcessMemory_6233 {
  strings:
    $key_6233 = { 35 41 [2] 07 63 [2] 01 56 [2] 2f 56 [2] 10 4a }

  condition:
    any of them
}