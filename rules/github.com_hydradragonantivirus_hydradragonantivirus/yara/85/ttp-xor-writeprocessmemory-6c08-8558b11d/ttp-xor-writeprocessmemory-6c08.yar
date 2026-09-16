rule TTP_XOR_WriteProcessMemory_6c08 {
  strings:
    $key_6c08 = { 3b 7a [2] 09 58 [2] 0f 6d [2] 21 6d [2] 1e 71 }

  condition:
    any of them
}