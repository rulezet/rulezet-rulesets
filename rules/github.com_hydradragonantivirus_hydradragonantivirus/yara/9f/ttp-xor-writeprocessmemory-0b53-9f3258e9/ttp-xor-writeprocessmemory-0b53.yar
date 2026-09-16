rule TTP_XOR_WriteProcessMemory_0b53 {
  strings:
    $key_0b53 = { 5c 21 [2] 6e 03 [2] 68 36 [2] 46 36 [2] 79 2a }

  condition:
    any of them
}