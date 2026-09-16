rule TTP_XOR_WriteProcessMemory_0a34 {
  strings:
    $key_0a34 = { 5d 46 [2] 6f 64 [2] 69 51 [2] 47 51 [2] 78 4d }

  condition:
    any of them
}