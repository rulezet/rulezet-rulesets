rule TTP_XOR_WriteProcessMemory_7149 {
  strings:
    $key_7149 = { 26 3b [2] 14 19 [2] 12 2c [2] 3c 2c [2] 03 30 }

  condition:
    any of them
}