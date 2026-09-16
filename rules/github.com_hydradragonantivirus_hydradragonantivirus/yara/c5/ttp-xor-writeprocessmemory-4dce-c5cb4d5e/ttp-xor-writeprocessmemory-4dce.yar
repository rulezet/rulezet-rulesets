rule TTP_XOR_WriteProcessMemory_4dce {
  strings:
    $key_4dce = { 1a bc [2] 28 9e [2] 2e ab [2] 00 ab [2] 3f b7 }

  condition:
    any of them
}