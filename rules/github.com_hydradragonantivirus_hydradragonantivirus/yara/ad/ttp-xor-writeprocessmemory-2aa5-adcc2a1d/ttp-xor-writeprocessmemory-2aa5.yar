rule TTP_XOR_WriteProcessMemory_2aa5 {
  strings:
    $key_2aa5 = { 7d d7 [2] 4f f5 [2] 49 c0 [2] 67 c0 [2] 58 dc }

  condition:
    any of them
}