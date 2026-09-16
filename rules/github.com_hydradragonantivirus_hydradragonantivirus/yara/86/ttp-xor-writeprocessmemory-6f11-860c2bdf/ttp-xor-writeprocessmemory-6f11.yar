rule TTP_XOR_WriteProcessMemory_6f11 {
  strings:
    $key_6f11 = { 38 63 [2] 0a 41 [2] 0c 74 [2] 22 74 [2] 1d 68 }

  condition:
    any of them
}