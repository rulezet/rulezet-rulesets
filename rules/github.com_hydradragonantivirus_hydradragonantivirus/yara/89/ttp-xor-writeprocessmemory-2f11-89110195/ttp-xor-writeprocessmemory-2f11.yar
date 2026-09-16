rule TTP_XOR_WriteProcessMemory_2f11 {
  strings:
    $key_2f11 = { 78 63 [2] 4a 41 [2] 4c 74 [2] 62 74 [2] 5d 68 }

  condition:
    any of them
}