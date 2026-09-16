rule TTP_XOR_WriteProcessMemory_39d2 {
  strings:
    $key_39d2 = { 6e a0 [2] 5c 82 [2] 5a b7 [2] 74 b7 [2] 4b ab }

  condition:
    any of them
}