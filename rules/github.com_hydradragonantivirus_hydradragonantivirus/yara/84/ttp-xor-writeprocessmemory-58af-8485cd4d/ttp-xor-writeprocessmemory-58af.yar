rule TTP_XOR_WriteProcessMemory_58af {
  strings:
    $key_58af = { 0f dd [2] 3d ff [2] 3b ca [2] 15 ca [2] 2a d6 }

  condition:
    any of them
}