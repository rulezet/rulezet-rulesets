rule TTP_XOR_WriteProcessMemory_d49a {
  strings:
    $key_d49a = { 83 e8 [2] b1 ca [2] b7 ff [2] 99 ff [2] a6 e3 }

  condition:
    any of them
}