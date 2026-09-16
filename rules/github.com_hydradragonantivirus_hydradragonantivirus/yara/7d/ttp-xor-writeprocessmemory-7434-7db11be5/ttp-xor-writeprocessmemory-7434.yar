rule TTP_XOR_WriteProcessMemory_7434 {
  strings:
    $key_7434 = { 23 46 [2] 11 64 [2] 17 51 [2] 39 51 [2] 06 4d }

  condition:
    any of them
}