rule TTP_XOR_WriteProcessMemory_3c34 {
  strings:
    $key_3c34 = { 6b 46 [2] 59 64 [2] 5f 51 [2] 71 51 [2] 4e 4d }

  condition:
    any of them
}