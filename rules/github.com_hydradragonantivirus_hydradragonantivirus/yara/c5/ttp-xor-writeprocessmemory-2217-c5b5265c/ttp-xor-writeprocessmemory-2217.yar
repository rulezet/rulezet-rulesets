rule TTP_XOR_WriteProcessMemory_2217 {
  strings:
    $key_2217 = { 75 65 [2] 47 47 [2] 41 72 [2] 6f 72 [2] 50 6e }

  condition:
    any of them
}