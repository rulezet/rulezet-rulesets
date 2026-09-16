rule TTP_XOR_WriteProcessMemory_e19a {
  strings:
    $key_e19a = { b6 e8 [2] 84 ca [2] 82 ff [2] ac ff [2] 93 e3 }

  condition:
    any of them
}