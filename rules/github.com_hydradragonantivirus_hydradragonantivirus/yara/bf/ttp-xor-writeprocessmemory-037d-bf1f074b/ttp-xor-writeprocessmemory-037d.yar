rule TTP_XOR_WriteProcessMemory_037d {
  strings:
    $key_037d = { 54 0f [2] 66 2d [2] 60 18 [2] 4e 18 [2] 71 04 }

  condition:
    any of them
}