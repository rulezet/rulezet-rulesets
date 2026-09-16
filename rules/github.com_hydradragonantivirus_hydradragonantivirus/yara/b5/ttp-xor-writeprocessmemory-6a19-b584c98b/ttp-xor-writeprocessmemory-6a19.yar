rule TTP_XOR_WriteProcessMemory_6a19 {
  strings:
    $key_6a19 = { 3d 6b [2] 0f 49 [2] 09 7c [2] 27 7c [2] 18 60 }

  condition:
    any of them
}