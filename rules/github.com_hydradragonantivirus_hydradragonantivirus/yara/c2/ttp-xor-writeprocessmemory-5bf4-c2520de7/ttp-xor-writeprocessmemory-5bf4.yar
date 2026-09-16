rule TTP_XOR_WriteProcessMemory_5bf4 {
  strings:
    $key_5bf4 = { 0c 86 [2] 3e a4 [2] 38 91 [2] 16 91 [2] 29 8d }

  condition:
    any of them
}