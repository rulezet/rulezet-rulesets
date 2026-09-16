rule TTP_XOR_WriteProcessMemory_6676 {
  strings:
    $key_6676 = { 31 04 [2] 03 26 [2] 05 13 [2] 2b 13 [2] 14 0f }

  condition:
    any of them
}