rule TTP_XOR_WriteProcessMemory_2858 {
  strings:
    $key_2858 = { 7f 2a [2] 4d 08 [2] 4b 3d [2] 65 3d [2] 5a 21 }

  condition:
    any of them
}