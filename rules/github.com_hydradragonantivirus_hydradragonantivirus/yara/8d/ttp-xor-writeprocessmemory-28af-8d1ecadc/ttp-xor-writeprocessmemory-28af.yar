rule TTP_XOR_WriteProcessMemory_28af {
  strings:
    $key_28af = { 7f dd [2] 4d ff [2] 4b ca [2] 65 ca [2] 5a d6 }

  condition:
    any of them
}