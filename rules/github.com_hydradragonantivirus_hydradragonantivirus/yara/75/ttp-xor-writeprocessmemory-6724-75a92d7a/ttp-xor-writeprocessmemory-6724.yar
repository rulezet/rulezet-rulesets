rule TTP_XOR_WriteProcessMemory_6724 {
  strings:
    $key_6724 = { 30 56 [2] 02 74 [2] 04 41 [2] 2a 41 [2] 15 5d }

  condition:
    any of them
}