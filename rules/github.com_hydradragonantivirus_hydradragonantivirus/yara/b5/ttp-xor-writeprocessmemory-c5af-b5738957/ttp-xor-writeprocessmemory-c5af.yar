rule TTP_XOR_WriteProcessMemory_c5af {
  strings:
    $key_c5af = { 92 dd [2] a0 ff [2] a6 ca [2] 88 ca [2] b7 d6 }

  condition:
    any of them
}