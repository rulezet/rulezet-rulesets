rule TTP_XOR_WriteProcessMemory_09a8 {
  strings:
    $key_09a8 = { 5e da [2] 6c f8 [2] 6a cd [2] 44 cd [2] 7b d1 }

  condition:
    any of them
}