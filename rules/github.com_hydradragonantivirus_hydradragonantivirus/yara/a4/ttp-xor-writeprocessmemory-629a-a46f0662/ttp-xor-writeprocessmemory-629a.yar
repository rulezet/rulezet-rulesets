rule TTP_XOR_WriteProcessMemory_629a {
  strings:
    $key_629a = { 35 e8 [2] 07 ca [2] 01 ff [2] 2f ff [2] 10 e3 }

  condition:
    any of them
}