rule TTP_XOR_WriteProcessMemory_7e37 {
  strings:
    $key_7e37 = { 29 45 [2] 1b 67 [2] 1d 52 [2] 33 52 [2] 0c 4e }

  condition:
    any of them
}