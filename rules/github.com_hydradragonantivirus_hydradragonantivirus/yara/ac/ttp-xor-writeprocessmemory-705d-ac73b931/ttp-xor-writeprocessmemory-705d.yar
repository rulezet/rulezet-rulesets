rule TTP_XOR_WriteProcessMemory_705d {
  strings:
    $key_705d = { 27 2f [2] 15 0d [2] 13 38 [2] 3d 38 [2] 02 24 }

  condition:
    any of them
}