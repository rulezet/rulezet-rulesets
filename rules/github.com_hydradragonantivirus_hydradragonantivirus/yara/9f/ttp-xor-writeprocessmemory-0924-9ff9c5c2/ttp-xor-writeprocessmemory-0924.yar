rule TTP_XOR_WriteProcessMemory_0924 {
  strings:
    $key_0924 = { 5e 56 [2] 6c 74 [2] 6a 41 [2] 44 41 [2] 7b 5d }

  condition:
    any of them
}