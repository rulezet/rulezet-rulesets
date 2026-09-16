rule TTP_XOR_WriteProcessMemory_5138 {
  strings:
    $key_5138 = { 06 4a [2] 34 68 [2] 32 5d [2] 1c 5d [2] 23 41 }

  condition:
    any of them
}