rule TTP_XOR_WriteProcessMemory_5bce {
  strings:
    $key_5bce = { 0c bc [2] 3e 9e [2] 38 ab [2] 16 ab [2] 29 b7 }

  condition:
    any of them
}