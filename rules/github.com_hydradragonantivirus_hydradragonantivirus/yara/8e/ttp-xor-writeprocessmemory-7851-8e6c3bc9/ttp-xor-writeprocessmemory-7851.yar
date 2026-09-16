rule TTP_XOR_WriteProcessMemory_7851 {
  strings:
    $key_7851 = { 2f 23 [2] 1d 01 [2] 1b 34 [2] 35 34 [2] 0a 28 }

  condition:
    any of them
}