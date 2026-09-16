rule TTP_XOR_WriteProcessMemory_7bce {
  strings:
    $key_7bce = { 2c bc [2] 1e 9e [2] 18 ab [2] 36 ab [2] 09 b7 }

  condition:
    any of them
}