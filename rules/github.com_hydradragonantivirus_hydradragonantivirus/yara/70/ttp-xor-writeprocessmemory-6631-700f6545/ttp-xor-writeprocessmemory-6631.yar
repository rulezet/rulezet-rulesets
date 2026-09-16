rule TTP_XOR_WriteProcessMemory_6631 {
  strings:
    $key_6631 = { 31 43 [2] 03 61 [2] 05 54 [2] 2b 54 [2] 14 48 }

  condition:
    any of them
}