rule TTP_XOR_WriteProcessMemory_61af {
  strings:
    $key_61af = { 36 dd [2] 04 ff [2] 02 ca [2] 2c ca [2] 13 d6 }

  condition:
    any of them
}