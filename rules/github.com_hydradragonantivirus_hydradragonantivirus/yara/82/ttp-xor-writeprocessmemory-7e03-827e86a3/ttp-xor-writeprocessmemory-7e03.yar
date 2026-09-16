rule TTP_XOR_WriteProcessMemory_7e03 {
  strings:
    $key_7e03 = { 29 71 [2] 1b 53 [2] 1d 66 [2] 33 66 [2] 0c 7a }

  condition:
    any of them
}