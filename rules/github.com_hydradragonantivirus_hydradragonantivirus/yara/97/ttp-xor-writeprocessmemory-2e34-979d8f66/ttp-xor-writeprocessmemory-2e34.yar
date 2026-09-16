rule TTP_XOR_WriteProcessMemory_2e34 {
  strings:
    $key_2e34 = { 79 46 [2] 4b 64 [2] 4d 51 [2] 63 51 [2] 5c 4d }

  condition:
    any of them
}