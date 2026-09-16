rule TTP_XOR_WriteProcessMemory_0652 {
  strings:
    $key_0652 = { 51 20 [2] 63 02 [2] 65 37 [2] 4b 37 [2] 74 2b }

  condition:
    any of them
}