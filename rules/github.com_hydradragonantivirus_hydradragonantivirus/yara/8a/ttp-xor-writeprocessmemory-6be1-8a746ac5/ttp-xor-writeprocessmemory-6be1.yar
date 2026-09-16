rule TTP_XOR_WriteProcessMemory_6be1 {
  strings:
    $key_6be1 = { 3c 93 [2] 0e b1 [2] 08 84 [2] 26 84 [2] 19 98 }

  condition:
    any of them
}