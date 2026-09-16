rule TTP_XOR_WriteProcessMemory_6bf1 {
  strings:
    $key_6bf1 = { 3c 83 [2] 0e a1 [2] 08 94 [2] 26 94 [2] 19 88 }

  condition:
    any of them
}