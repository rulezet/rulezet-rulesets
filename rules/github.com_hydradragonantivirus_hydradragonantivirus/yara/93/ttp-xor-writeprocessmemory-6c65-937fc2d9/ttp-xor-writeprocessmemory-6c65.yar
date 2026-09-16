rule TTP_XOR_WriteProcessMemory_6c65 {
  strings:
    $key_6c65 = { 3b 17 [2] 09 35 [2] 0f 00 [2] 21 00 [2] 1e 1c }

  condition:
    any of them
}