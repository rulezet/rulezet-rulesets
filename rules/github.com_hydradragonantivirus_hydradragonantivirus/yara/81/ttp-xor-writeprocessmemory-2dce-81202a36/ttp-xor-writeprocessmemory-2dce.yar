rule TTP_XOR_WriteProcessMemory_2dce {
  strings:
    $key_2dce = { 7a bc [2] 48 9e [2] 4e ab [2] 60 ab [2] 5f b7 }

  condition:
    any of them
}