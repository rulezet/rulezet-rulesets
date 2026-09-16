rule TTP_XOR_WriteProcessMemory_0e18 {
  strings:
    $key_0e18 = { 59 6a [2] 6b 48 [2] 6d 7d [2] 43 7d [2] 7c 61 }

  condition:
    any of them
}