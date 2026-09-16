rule TTP_XOR_WriteProcessMemory_0943 {
  strings:
    $key_0943 = { 5e 31 [2] 6c 13 [2] 6a 26 [2] 44 26 [2] 7b 3a }

  condition:
    any of them
}