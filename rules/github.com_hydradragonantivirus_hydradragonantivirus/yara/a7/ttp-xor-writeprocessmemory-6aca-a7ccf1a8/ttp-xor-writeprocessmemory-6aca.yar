rule TTP_XOR_WriteProcessMemory_6aca {
  strings:
    $key_6aca = { 3d b8 [2] 0f 9a [2] 09 af [2] 27 af [2] 18 b3 }

  condition:
    any of them
}