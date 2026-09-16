rule TTP_XOR_WriteProcessMemory_7069 {
  strings:
    $key_7069 = { 27 1b [2] 15 39 [2] 13 0c [2] 3d 0c [2] 02 10 }

  condition:
    any of them
}