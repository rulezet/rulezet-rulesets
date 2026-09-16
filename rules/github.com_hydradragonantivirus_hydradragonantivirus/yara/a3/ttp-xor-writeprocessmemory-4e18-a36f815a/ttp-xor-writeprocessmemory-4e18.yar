rule TTP_XOR_WriteProcessMemory_4e18 {
  strings:
    $key_4e18 = { 19 6a [2] 2b 48 [2] 2d 7d [2] 03 7d [2] 3c 61 }

  condition:
    any of them
}