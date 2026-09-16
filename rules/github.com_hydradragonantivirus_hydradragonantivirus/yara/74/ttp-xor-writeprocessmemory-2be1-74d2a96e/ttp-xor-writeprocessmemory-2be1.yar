rule TTP_XOR_WriteProcessMemory_2be1 {
  strings:
    $key_2be1 = { 7c 93 [2] 4e b1 [2] 48 84 [2] 66 84 [2] 59 98 }

  condition:
    any of them
}