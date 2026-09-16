rule TTP_XOR_WriteProcessMemory_1e31 {
  strings:
    $key_1e31 = { 49 43 [2] 7b 61 [2] 7d 54 [2] 53 54 [2] 6c 48 }

  condition:
    any of them
}