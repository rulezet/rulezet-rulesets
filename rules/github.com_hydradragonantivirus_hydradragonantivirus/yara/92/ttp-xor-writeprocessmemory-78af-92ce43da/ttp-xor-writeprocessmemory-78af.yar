rule TTP_XOR_WriteProcessMemory_78af {
  strings:
    $key_78af = { 2f dd [2] 1d ff [2] 1b ca [2] 35 ca [2] 0a d6 }

  condition:
    any of them
}