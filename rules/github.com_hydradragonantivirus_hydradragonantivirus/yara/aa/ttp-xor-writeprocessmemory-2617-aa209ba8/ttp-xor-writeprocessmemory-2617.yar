rule TTP_XOR_WriteProcessMemory_2617 {
  strings:
    $key_2617 = { 71 65 [2] 43 47 [2] 45 72 [2] 6b 72 [2] 54 6e }

  condition:
    any of them
}