rule TTP_XOR_WriteProcessMemory_7e31 {
  strings:
    $key_7e31 = { 29 43 [2] 1b 61 [2] 1d 54 [2] 33 54 [2] 0c 48 }

  condition:
    any of them
}