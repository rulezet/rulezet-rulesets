rule TTP_XOR_WriteProcessMemory_7877 {
  strings:
    $key_7877 = { 2f 05 [2] 1d 27 [2] 1b 12 [2] 35 12 [2] 0a 0e }

  condition:
    any of them
}