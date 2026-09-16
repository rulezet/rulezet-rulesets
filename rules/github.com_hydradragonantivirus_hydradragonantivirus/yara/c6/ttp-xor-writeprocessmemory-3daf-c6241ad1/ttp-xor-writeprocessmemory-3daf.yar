rule TTP_XOR_WriteProcessMemory_3daf {
  strings:
    $key_3daf = { 6a dd [2] 58 ff [2] 5e ca [2] 70 ca [2] 4f d6 }

  condition:
    any of them
}