rule TTP_XOR_WriteProcessMemory_4174 {
  strings:
    $key_4174 = { 16 06 [2] 24 24 [2] 22 11 [2] 0c 11 [2] 33 0d }

  condition:
    any of them
}