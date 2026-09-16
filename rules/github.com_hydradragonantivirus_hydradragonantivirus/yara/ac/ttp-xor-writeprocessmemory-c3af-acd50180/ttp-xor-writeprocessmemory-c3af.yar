rule TTP_XOR_WriteProcessMemory_c3af {
  strings:
    $key_c3af = { 94 dd [2] a6 ff [2] a0 ca [2] 8e ca [2] b1 d6 }

  condition:
    any of them
}