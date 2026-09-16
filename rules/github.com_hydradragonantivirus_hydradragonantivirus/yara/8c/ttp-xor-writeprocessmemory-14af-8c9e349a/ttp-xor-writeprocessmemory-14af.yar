rule TTP_XOR_WriteProcessMemory_14af {
  strings:
    $key_14af = { 43 dd [2] 71 ff [2] 77 ca [2] 59 ca [2] 66 d6 }

  condition:
    any of them
}