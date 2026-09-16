rule TTP_XOR_WriteProcessMemory_3774 {
  strings:
    $key_3774 = { 60 06 [2] 52 24 [2] 54 11 [2] 7a 11 [2] 45 0d }

  condition:
    any of them
}