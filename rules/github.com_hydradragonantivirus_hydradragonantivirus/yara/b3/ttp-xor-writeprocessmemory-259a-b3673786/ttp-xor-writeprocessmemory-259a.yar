rule TTP_XOR_WriteProcessMemory_259a {
  strings:
    $key_259a = { 72 e8 [2] 40 ca [2] 46 ff [2] 68 ff [2] 57 e3 }

  condition:
    any of them
}