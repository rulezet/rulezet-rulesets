rule TTP_XOR_WriteProcessMemory_49a8 {
  strings:
    $key_49a8 = { 1e da [2] 2c f8 [2] 2a cd [2] 04 cd [2] 3b d1 }

  condition:
    any of them
}