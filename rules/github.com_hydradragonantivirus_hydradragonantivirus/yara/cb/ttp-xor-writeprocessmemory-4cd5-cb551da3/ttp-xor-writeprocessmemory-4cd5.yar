rule TTP_XOR_WriteProcessMemory_4cd5 {
  strings:
    $key_4cd5 = { 1b a7 [2] 29 85 [2] 2f b0 [2] 01 b0 [2] 3e ac }

  condition:
    any of them
}