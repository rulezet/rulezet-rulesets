rule TTP_XOR_WriteProcessMemory_7e36 {
  strings:
    $key_7e36 = { 29 44 [2] 1b 66 [2] 1d 53 [2] 33 53 [2] 0c 4f }

  condition:
    any of them
}