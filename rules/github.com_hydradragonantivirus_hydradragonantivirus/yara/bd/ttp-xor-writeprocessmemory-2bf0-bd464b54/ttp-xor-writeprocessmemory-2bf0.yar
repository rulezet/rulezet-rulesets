rule TTP_XOR_WriteProcessMemory_2bf0 {
  strings:
    $key_2bf0 = { 7c 82 [2] 4e a0 [2] 48 95 [2] 66 95 [2] 59 89 }

  condition:
    any of them
}