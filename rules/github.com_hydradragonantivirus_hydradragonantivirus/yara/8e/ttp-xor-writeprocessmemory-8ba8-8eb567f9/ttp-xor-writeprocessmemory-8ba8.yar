rule TTP_XOR_WriteProcessMemory_8ba8 {
  strings:
    $key_8ba8 = { dc da [2] ee f8 [2] e8 cd [2] c6 cd [2] f9 d1 }

  condition:
    any of them
}