rule TTP_XOR_WriteProcessMemory_4034 {
  strings:
    $key_4034 = { 17 46 [2] 25 64 [2] 23 51 [2] 0d 51 [2] 32 4d }

  condition:
    any of them
}