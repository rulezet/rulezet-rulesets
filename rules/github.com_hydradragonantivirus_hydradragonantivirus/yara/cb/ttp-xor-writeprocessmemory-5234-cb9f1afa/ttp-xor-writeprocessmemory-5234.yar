rule TTP_XOR_WriteProcessMemory_5234 {
  strings:
    $key_5234 = { 05 46 [2] 37 64 [2] 31 51 [2] 1f 51 [2] 20 4d }

  condition:
    any of them
}