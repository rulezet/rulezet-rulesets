rule TTP_XOR_WriteProcessMemory_6dcd {
  strings:
    $key_6dcd = { 3a bf [2] 08 9d [2] 0e a8 [2] 20 a8 [2] 1f b4 }

  condition:
    any of them
}