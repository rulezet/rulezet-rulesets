rule TTP_XOR_WriteProcessMemory_3bce {
  strings:
    $key_3bce = { 6c bc [2] 5e 9e [2] 58 ab [2] 76 ab [2] 49 b7 }

  condition:
    any of them
}