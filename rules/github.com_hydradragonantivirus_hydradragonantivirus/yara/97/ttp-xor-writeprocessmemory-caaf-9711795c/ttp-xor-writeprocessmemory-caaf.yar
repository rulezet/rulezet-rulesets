rule TTP_XOR_WriteProcessMemory_caaf {
  strings:
    $key_caaf = { 9d dd [2] af ff [2] a9 ca [2] 87 ca [2] b8 d6 }

  condition:
    any of them
}