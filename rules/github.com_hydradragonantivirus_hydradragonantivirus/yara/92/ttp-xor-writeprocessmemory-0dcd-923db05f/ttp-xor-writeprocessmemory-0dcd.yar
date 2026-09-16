rule TTP_XOR_WriteProcessMemory_0dcd {
  strings:
    $key_0dcd = { 5a bf [2] 68 9d [2] 6e a8 [2] 40 a8 [2] 7f b4 }

  condition:
    any of them
}