rule TTP_XOR_WriteProcessMemory_6bce {
  strings:
    $key_6bce = { 3c bc [2] 0e 9e [2] 08 ab [2] 26 ab [2] 19 b7 }

  condition:
    any of them
}