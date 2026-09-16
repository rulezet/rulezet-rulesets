rule TTP_XOR_WriteProcessMemory_6a59 {
  strings:
    $key_6a59 = { 3d 2b [2] 0f 09 [2] 09 3c [2] 27 3c [2] 18 20 }

  condition:
    any of them
}