rule TTP_XOR_WriteProcessMemory_4634 {
  strings:
    $key_4634 = { 11 46 [2] 23 64 [2] 25 51 [2] 0b 51 [2] 34 4d }

  condition:
    any of them
}