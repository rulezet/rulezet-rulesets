rule TTP_XOR_WriteProcessMemory_5869 {
  strings:
    $key_5869 = { 0f 1b [2] 3d 39 [2] 3b 0c [2] 15 0c [2] 2a 10 }

  condition:
    any of them
}