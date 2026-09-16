rule TTP_XOR_WriteProcessMemory_6d9a {
  strings:
    $key_6d9a = { 3a e8 [2] 08 ca [2] 0e ff [2] 20 ff [2] 1f e3 }

  condition:
    any of them
}