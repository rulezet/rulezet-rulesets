rule TTP_XOR_WriteProcessMemory_3971 {
  strings:
    $key_3971 = { 6e 03 [2] 5c 21 [2] 5a 14 [2] 74 14 [2] 4b 08 }

  condition:
    any of them
}