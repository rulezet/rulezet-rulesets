rule TTP_XOR_WriteProcessMemory_0630 {
  strings:
    $key_0630 = { 51 42 [2] 63 60 [2] 65 55 [2] 4b 55 [2] 74 49 }

  condition:
    any of them
}