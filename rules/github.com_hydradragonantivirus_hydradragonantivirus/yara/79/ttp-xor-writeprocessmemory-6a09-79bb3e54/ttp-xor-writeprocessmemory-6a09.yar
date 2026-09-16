rule TTP_XOR_WriteProcessMemory_6a09 {
  strings:
    $key_6a09 = { 3d 7b [2] 0f 59 [2] 09 6c [2] 27 6c [2] 18 70 }

  condition:
    any of them
}