rule TTP_XOR_WriteProcessMemory_6c53 {
  strings:
    $key_6c53 = { 3b 21 [2] 09 03 [2] 0f 36 [2] 21 36 [2] 1e 2a }

  condition:
    any of them
}