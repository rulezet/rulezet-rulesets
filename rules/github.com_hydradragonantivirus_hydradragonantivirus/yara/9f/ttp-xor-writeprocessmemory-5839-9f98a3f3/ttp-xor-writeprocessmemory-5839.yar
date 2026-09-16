rule TTP_XOR_WriteProcessMemory_5839 {
  strings:
    $key_5839 = { 0f 4b [2] 3d 69 [2] 3b 5c [2] 15 5c [2] 2a 40 }

  condition:
    any of them
}