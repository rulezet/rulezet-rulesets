rule TTP_XOR_WriteProcessMemory_fcaf {
  strings:
    $key_fcaf = { ab dd [2] 99 ff [2] 9f ca [2] b1 ca [2] 8e d6 }

  condition:
    any of them
}