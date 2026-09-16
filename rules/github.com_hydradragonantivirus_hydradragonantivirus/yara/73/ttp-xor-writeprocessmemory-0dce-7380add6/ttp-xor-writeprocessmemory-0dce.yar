rule TTP_XOR_WriteProcessMemory_0dce {
  strings:
    $key_0dce = { 5a bc [2] 68 9e [2] 6e ab [2] 40 ab [2] 7f b7 }

  condition:
    any of them
}