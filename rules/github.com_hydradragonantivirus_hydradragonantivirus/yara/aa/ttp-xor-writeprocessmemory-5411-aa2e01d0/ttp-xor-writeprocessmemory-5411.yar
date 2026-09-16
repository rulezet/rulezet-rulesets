rule TTP_XOR_WriteProcessMemory_5411 {
  strings:
    $key_5411 = { 03 63 [2] 31 41 [2] 37 74 [2] 19 74 [2] 26 68 }

  condition:
    any of them
}