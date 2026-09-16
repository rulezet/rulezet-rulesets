rule TTP_XOR_WriteProcessMemory_29a8 {
  strings:
    $key_29a8 = { 7e da [2] 4c f8 [2] 4a cd [2] 64 cd [2] 5b d1 }

  condition:
    any of them
}