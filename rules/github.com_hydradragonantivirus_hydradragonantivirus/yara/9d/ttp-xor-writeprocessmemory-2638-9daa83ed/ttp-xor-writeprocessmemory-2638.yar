rule TTP_XOR_WriteProcessMemory_2638 {
  strings:
    $key_2638 = { 71 4a [2] 43 68 [2] 45 5d [2] 6b 5d [2] 54 41 }

  condition:
    any of them
}