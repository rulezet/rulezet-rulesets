rule TTP_XOR_WriteProcessMemory_3204 {
  strings:
    $key_3204 = { 65 76 [2] 57 54 [2] 51 61 [2] 7f 61 [2] 40 7d }

  condition:
    any of them
}