rule TTP_XOR_WriteProcessMemory_7804 {
  strings:
    $key_7804 = { 2f 76 [2] 1d 54 [2] 1b 61 [2] 35 61 [2] 0a 7d }

  condition:
    any of them
}