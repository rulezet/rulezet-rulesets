rule TTP_XOR_WriteProcessMemory_4d9a {
  strings:
    $key_4d9a = { 1a e8 [2] 28 ca [2] 2e ff [2] 00 ff [2] 3f e3 }

  condition:
    any of them
}