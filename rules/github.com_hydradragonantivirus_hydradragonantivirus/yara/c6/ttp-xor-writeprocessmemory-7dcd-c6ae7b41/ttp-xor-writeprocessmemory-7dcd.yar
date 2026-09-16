rule TTP_XOR_WriteProcessMemory_7dcd {
  strings:
    $key_7dcd = { 2a bf [2] 18 9d [2] 1e a8 [2] 30 a8 [2] 0f b4 }

  condition:
    any of them
}