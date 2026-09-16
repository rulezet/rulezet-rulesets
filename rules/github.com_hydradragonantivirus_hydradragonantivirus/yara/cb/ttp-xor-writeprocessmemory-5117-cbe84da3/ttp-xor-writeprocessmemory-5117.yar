rule TTP_XOR_WriteProcessMemory_5117 {
  strings:
    $key_5117 = { 06 65 [2] 34 47 [2] 32 72 [2] 1c 72 [2] 23 6e }

  condition:
    any of them
}