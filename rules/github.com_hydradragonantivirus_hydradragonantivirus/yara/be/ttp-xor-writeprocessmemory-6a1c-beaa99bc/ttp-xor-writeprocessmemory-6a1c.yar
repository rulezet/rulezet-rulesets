rule TTP_XOR_WriteProcessMemory_6a1c {
  strings:
    $key_6a1c = { 3d 6e [2] 0f 4c [2] 09 79 [2] 27 79 [2] 18 65 }

  condition:
    any of them
}