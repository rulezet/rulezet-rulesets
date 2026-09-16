rule TTP_XOR_WriteProcessMemory_d3af {
  strings:
    $key_d3af = { 84 dd [2] b6 ff [2] b0 ca [2] 9e ca [2] a1 d6 }

  condition:
    any of them
}