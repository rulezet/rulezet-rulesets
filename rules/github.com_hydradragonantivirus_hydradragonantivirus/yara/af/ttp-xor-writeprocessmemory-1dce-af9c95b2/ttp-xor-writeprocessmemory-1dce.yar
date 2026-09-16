rule TTP_XOR_WriteProcessMemory_1dce {
  strings:
    $key_1dce = { 4a bc [2] 78 9e [2] 7e ab [2] 50 ab [2] 6f b7 }

  condition:
    any of them
}