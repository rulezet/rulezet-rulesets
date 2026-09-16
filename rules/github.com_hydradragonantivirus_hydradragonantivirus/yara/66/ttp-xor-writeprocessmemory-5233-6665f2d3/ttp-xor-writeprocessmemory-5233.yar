rule TTP_XOR_WriteProcessMemory_5233 {
  strings:
    $key_5233 = { 05 41 [2] 37 63 [2] 31 56 [2] 1f 56 [2] 20 4a }

  condition:
    any of them
}