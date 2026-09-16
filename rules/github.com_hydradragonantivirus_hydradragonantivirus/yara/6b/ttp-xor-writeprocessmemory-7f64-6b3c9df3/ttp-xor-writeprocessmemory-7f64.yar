rule TTP_XOR_WriteProcessMemory_7f64 {
  strings:
    $key_7f64 = { 28 16 [2] 1a 34 [2] 1c 01 [2] 32 01 [2] 0d 1d }

  condition:
    any of them
}