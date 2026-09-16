rule TTP_XOR_WriteProcessMemory_229a {
  strings:
    $key_229a = { 75 e8 [2] 47 ca [2] 41 ff [2] 6f ff [2] 50 e3 }

  condition:
    any of them
}