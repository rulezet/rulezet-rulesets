rule TTP_XOR_WriteProcessMemory_3ad2 {
  strings:
    $key_3ad2 = { 6d a0 [2] 5f 82 [2] 59 b7 [2] 77 b7 [2] 48 ab }

  condition:
    any of them
}