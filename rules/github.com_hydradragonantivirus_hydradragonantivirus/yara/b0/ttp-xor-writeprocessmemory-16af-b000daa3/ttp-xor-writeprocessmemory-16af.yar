rule TTP_XOR_WriteProcessMemory_16af {
  strings:
    $key_16af = { 41 dd [2] 73 ff [2] 75 ca [2] 5b ca [2] 64 d6 }

  condition:
    any of them
}