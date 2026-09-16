rule TTP_XOR_WriteProcessMemory_729a {
  strings:
    $key_729a = { 25 e8 [2] 17 ca [2] 11 ff [2] 3f ff [2] 00 e3 }

  condition:
    any of them
}