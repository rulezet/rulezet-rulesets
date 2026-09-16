rule TTP_XOR_WriteProcessMemory_e49a {
  strings:
    $key_e49a = { b3 e8 [2] 81 ca [2] 87 ff [2] a9 ff [2] 96 e3 }

  condition:
    any of them
}