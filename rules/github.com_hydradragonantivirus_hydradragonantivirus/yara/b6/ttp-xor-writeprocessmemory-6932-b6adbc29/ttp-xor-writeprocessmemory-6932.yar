rule TTP_XOR_WriteProcessMemory_6932 {
  strings:
    $key_6932 = { 3e 40 [2] 0c 62 [2] 0a 57 [2] 24 57 [2] 1b 4b }

  condition:
    any of them
}