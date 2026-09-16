rule TTP_XOR_WriteProcessMemory_d5af {
  strings:
    $key_d5af = { 82 dd [2] b0 ff [2] b6 ca [2] 98 ca [2] a7 d6 }

  condition:
    any of them
}