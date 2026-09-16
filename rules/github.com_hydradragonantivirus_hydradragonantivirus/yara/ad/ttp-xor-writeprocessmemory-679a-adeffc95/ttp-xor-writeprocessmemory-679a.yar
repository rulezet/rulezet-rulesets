rule TTP_XOR_WriteProcessMemory_679a {
  strings:
    $key_679a = { 30 e8 [2] 02 ca [2] 04 ff [2] 2a ff [2] 15 e3 }

  condition:
    any of them
}