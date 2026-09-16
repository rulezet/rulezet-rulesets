rule TTP_XOR_WriteProcessMemory_5819 {
  strings:
    $key_5819 = { 0f 6b [2] 3d 49 [2] 3b 7c [2] 15 7c [2] 2a 60 }

  condition:
    any of them
}