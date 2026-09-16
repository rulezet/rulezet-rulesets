rule TTP_XOR_WriteProcessMemory_4404 {
  strings:
    $key_4404 = { 13 76 [2] 21 54 [2] 27 61 [2] 09 61 [2] 36 7d }

  condition:
    any of them
}