rule TTP_XOR_WriteProcessMemory_7d79 {
  strings:
    $key_7d79 = { 2a 0b [2] 18 29 [2] 1e 1c [2] 30 1c [2] 0f 00 }

  condition:
    any of them
}