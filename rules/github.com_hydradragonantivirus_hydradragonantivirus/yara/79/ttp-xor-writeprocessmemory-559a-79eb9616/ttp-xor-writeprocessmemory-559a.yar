rule TTP_XOR_WriteProcessMemory_559a {
  strings:
    $key_559a = { 02 e8 [2] 30 ca [2] 36 ff [2] 18 ff [2] 27 e3 }

  condition:
    any of them
}