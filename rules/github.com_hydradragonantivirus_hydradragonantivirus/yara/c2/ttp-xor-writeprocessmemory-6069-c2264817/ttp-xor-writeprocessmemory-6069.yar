rule TTP_XOR_WriteProcessMemory_6069 {
  strings:
    $key_6069 = { 37 1b [2] 05 39 [2] 03 0c [2] 2d 0c [2] 12 10 }

  condition:
    any of them
}