rule TTP_XOR_WriteProcessMemory_7062 {
  strings:
    $key_7062 = { 27 10 [2] 15 32 [2] 13 07 [2] 3d 07 [2] 02 1b }

  condition:
    any of them
}