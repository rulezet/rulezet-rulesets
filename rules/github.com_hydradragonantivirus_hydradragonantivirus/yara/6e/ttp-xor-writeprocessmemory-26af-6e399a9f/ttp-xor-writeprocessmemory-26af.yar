rule TTP_XOR_WriteProcessMemory_26af {
  strings:
    $key_26af = { 71 dd [2] 43 ff [2] 45 ca [2] 6b ca [2] 54 d6 }

  condition:
    any of them
}