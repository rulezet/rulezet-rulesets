rule TTP_XOR_WriteProcessMemory_6a75 {
  strings:
    $key_6a75 = { 3d 07 [2] 0f 25 [2] 09 10 [2] 27 10 [2] 18 0c }

  condition:
    any of them
}