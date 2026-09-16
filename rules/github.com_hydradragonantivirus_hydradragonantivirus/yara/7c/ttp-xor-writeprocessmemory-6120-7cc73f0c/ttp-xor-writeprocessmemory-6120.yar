rule TTP_XOR_WriteProcessMemory_6120 {
  strings:
    $key_6120 = { 36 52 [2] 04 70 [2] 02 45 [2] 2c 45 [2] 13 59 }

  condition:
    any of them
}