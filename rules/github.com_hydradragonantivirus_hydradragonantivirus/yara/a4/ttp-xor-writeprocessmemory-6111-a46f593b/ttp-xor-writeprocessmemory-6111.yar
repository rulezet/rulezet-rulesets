rule TTP_XOR_WriteProcessMemory_6111 {
  strings:
    $key_6111 = { 36 63 [2] 04 41 [2] 02 74 [2] 2c 74 [2] 13 68 }

  condition:
    any of them
}