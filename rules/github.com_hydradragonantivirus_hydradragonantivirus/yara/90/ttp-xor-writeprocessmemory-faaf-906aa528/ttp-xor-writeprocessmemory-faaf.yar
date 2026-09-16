rule TTP_XOR_WriteProcessMemory_faaf {
  strings:
    $key_faaf = { ad dd [2] 9f ff [2] 99 ca [2] b7 ca [2] 88 d6 }

  condition:
    any of them
}