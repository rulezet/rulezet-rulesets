rule TTP_XOR_WriteProcessMemory_4f64 {
  strings:
    $key_4f64 = { 18 16 [2] 2a 34 [2] 2c 01 [2] 02 01 [2] 3d 1d }

  condition:
    any of them
}