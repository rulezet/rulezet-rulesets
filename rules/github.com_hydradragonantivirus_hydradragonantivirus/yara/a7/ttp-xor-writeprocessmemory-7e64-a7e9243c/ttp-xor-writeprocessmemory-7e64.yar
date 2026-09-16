rule TTP_XOR_WriteProcessMemory_7e64 {
  strings:
    $key_7e64 = { 29 16 [2] 1b 34 [2] 1d 01 [2] 33 01 [2] 0c 1d }

  condition:
    any of them
}