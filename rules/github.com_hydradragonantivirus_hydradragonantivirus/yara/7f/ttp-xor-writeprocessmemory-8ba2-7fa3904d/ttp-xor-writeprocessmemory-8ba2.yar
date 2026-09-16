rule TTP_XOR_WriteProcessMemory_8ba2 {
  strings:
    $key_8ba2 = { dc d0 [2] ee f2 [2] e8 c7 [2] c6 c7 [2] f9 db }

  condition:
    any of them
}