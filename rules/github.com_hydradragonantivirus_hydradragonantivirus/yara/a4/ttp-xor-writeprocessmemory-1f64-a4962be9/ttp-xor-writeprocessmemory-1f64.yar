rule TTP_XOR_WriteProcessMemory_1f64 {
  strings:
    $key_1f64 = { 48 16 [2] 7a 34 [2] 7c 01 [2] 52 01 [2] 6d 1d }

  condition:
    any of them
}