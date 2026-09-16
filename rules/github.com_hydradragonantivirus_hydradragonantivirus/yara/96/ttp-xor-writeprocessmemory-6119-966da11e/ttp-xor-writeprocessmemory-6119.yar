rule TTP_XOR_WriteProcessMemory_6119 {
  strings:
    $key_6119 = { 36 6b [2] 04 49 [2] 02 7c [2] 2c 7c [2] 13 60 }

  condition:
    any of them
}