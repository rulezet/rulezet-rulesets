rule TTP_XOR_WriteProcessMemory_6a05 {
  strings:
    $key_6a05 = { 3d 77 [2] 0f 55 [2] 09 60 [2] 27 60 [2] 18 7c }

  condition:
    any of them
}