rule TTP_XOR_WriteProcessMemory_838d {
  strings:
    $key_838d = { d4 ff [2] e6 dd [2] e0 e8 [2] ce e8 [2] f1 f4 }

  condition:
    any of them
}