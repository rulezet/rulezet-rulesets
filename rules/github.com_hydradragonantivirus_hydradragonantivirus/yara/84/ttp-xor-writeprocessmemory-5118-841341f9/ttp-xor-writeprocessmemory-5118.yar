rule TTP_XOR_WriteProcessMemory_5118 {
  strings:
    $key_5118 = { 06 6a [2] 34 48 [2] 32 7d [2] 1c 7d [2] 23 61 }

  condition:
    any of them
}