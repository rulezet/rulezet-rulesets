rule TTP_XOR_WriteProcessMemory_e39a {
  strings:
    $key_e39a = { b4 e8 [2] 86 ca [2] 80 ff [2] ae ff [2] 91 e3 }

  condition:
    any of them
}