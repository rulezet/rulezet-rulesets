rule TTP_XOR_WriteProcessMemory_c0af {
  strings:
    $key_c0af = { 97 dd [2] a5 ff [2] a3 ca [2] 8d ca [2] b2 d6 }

  condition:
    any of them
}