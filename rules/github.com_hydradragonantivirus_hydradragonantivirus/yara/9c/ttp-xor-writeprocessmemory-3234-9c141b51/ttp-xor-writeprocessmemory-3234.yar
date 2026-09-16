rule TTP_XOR_WriteProcessMemory_3234 {
  strings:
    $key_3234 = { 65 46 [2] 57 64 [2] 51 51 [2] 7f 51 [2] 40 4d }

  condition:
    any of them
}