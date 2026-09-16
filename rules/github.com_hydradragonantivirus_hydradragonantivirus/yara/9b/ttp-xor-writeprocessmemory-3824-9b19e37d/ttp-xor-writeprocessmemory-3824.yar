rule TTP_XOR_WriteProcessMemory_3824 {
  strings:
    $key_3824 = { 6f 56 [2] 5d 74 [2] 5b 41 [2] 75 41 [2] 4a 5d }

  condition:
    any of them
}