rule TTP_XOR_WriteProcessMemory_329a {
  strings:
    $key_329a = { 65 e8 [2] 57 ca [2] 51 ff [2] 7f ff [2] 40 e3 }

  condition:
    any of them
}