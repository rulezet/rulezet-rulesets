rule TTP_XOR_WriteProcessMemory_6a39 {
  strings:
    $key_6a39 = { 3d 4b [2] 0f 69 [2] 09 5c [2] 27 5c [2] 18 40 }

  condition:
    any of them
}