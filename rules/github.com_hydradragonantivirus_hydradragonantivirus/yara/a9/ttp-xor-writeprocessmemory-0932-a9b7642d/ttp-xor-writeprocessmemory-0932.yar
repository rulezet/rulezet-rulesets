rule TTP_XOR_WriteProcessMemory_0932 {
  strings:
    $key_0932 = { 5e 40 [2] 6c 62 [2] 6a 57 [2] 44 57 [2] 7b 4b }

  condition:
    any of them
}