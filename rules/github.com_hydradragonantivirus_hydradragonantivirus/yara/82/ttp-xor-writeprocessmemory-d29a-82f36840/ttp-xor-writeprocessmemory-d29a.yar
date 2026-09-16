rule TTP_XOR_WriteProcessMemory_d29a {
  strings:
    $key_d29a = { 85 e8 [2] b7 ca [2] b1 ff [2] 9f ff [2] a0 e3 }

  condition:
    any of them
}