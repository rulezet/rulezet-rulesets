rule TTP_XOR_WriteProcessMemory_6b53 {
  strings:
    $key_6b53 = { 3c 21 [2] 0e 03 [2] 08 36 [2] 26 36 [2] 19 2a }

  condition:
    any of them
}