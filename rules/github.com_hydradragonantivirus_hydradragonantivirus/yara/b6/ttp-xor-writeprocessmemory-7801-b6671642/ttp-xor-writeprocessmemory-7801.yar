rule TTP_XOR_WriteProcessMemory_7801 {
  strings:
    $key_7801 = { 2f 73 [2] 1d 51 [2] 1b 64 [2] 35 64 [2] 0a 78 }

  condition:
    any of them
}