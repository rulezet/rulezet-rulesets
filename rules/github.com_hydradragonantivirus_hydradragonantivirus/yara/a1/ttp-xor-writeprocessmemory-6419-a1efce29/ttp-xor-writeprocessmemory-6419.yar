rule TTP_XOR_WriteProcessMemory_6419 {
  strings:
    $key_6419 = { 33 6b [2] 01 49 [2] 07 7c [2] 29 7c [2] 16 60 }

  condition:
    any of them
}