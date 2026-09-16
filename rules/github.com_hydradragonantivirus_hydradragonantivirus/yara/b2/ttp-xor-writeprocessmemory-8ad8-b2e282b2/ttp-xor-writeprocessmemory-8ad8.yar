rule TTP_XOR_WriteProcessMemory_8ad8 {
  strings:
    $key_8ad8 = { dd aa [2] ef 88 [2] e9 bd [2] c7 bd [2] f8 a1 }

  condition:
    any of them
}