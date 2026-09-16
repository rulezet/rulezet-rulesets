rule TTP_XOR_WriteProcessMemory_3b53 {
  strings:
    $key_3b53 = { 6c 21 [2] 5e 03 [2] 58 36 [2] 76 36 [2] 49 2a }

  condition:
    any of them
}