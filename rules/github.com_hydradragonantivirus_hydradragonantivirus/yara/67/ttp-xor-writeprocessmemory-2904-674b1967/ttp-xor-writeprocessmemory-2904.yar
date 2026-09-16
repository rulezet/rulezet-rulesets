rule TTP_XOR_WriteProcessMemory_2904 {
  strings:
    $key_2904 = { 7e 76 [2] 4c 54 [2] 4a 61 [2] 64 61 [2] 5b 7d }

  condition:
    any of them
}