rule TTP_XOR_WriteProcessMemory_066d {
  strings:
    $key_066d = { 51 1f [2] 63 3d [2] 65 08 [2] 4b 08 [2] 74 14 }

  condition:
    any of them
}