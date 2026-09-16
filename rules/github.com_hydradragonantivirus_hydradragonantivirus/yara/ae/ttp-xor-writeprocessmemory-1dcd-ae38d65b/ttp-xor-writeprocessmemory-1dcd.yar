rule TTP_XOR_WriteProcessMemory_1dcd {
  strings:
    $key_1dcd = { 4a bf [2] 78 9d [2] 7e a8 [2] 50 a8 [2] 6f b4 }

  condition:
    any of them
}