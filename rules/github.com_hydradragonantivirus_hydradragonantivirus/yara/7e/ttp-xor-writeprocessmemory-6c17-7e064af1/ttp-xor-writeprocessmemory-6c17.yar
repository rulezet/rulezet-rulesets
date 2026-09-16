rule TTP_XOR_WriteProcessMemory_6c17 {
  strings:
    $key_6c17 = { 3b 65 [2] 09 47 [2] 0f 72 [2] 21 72 [2] 1e 6e }

  condition:
    any of them
}