rule TTP_XOR_WriteProcessMemory_828d {
  strings:
    $key_828d = { d5 ff [2] e7 dd [2] e1 e8 [2] cf e8 [2] f0 f4 }

  condition:
    any of them
}