rule TTP_XOR_WriteProcessMemory_48af {
  strings:
    $key_48af = { 1f dd [2] 2d ff [2] 2b ca [2] 05 ca [2] 3a d6 }

  condition:
    any of them
}