rule TTP_XOR_WriteProcessMemory_7e34 {
  strings:
    $key_7e34 = { 29 46 [2] 1b 64 [2] 1d 51 [2] 33 51 [2] 0c 4d }

  condition:
    any of them
}