rule TTP_XOR_WriteProcessMemory_6147 {
  strings:
    $key_6147 = { 36 35 [2] 04 17 [2] 02 22 [2] 2c 22 [2] 13 3e }

  condition:
    any of them
}