rule TTP_XOR_WriteProcessMemory_1b53 {
  strings:
    $key_1b53 = { 4c 21 [2] 7e 03 [2] 78 36 [2] 56 36 [2] 69 2a }

  condition:
    any of them
}