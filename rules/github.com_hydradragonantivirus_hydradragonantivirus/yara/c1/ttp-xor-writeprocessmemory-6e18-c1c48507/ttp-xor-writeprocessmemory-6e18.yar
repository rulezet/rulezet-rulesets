rule TTP_XOR_WriteProcessMemory_6e18 {
  strings:
    $key_6e18 = { 39 6a [2] 0b 48 [2] 0d 7d [2] 23 7d [2] 1c 61 }

  condition:
    any of them
}