rule TTP_XOR_WriteProcessMemory_4831 {
  strings:
    $key_4831 = { 1f 43 [2] 2d 61 [2] 2b 54 [2] 05 54 [2] 3a 48 }

  condition:
    any of them
}