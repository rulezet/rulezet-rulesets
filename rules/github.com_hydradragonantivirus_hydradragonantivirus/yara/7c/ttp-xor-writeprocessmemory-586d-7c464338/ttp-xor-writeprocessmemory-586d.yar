rule TTP_XOR_WriteProcessMemory_586d {
  strings:
    $key_586d = { 0f 1f [2] 3d 3d [2] 3b 08 [2] 15 08 [2] 2a 14 }

  condition:
    any of them
}