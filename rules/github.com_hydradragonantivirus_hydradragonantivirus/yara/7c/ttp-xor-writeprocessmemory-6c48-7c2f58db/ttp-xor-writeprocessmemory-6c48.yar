rule TTP_XOR_WriteProcessMemory_6c48 {
  strings:
    $key_6c48 = { 3b 3a [2] 09 18 [2] 0f 2d [2] 21 2d [2] 1e 31 }

  condition:
    any of them
}