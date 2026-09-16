rule TTP_XOR_WriteProcessMemory_0d9a {
  strings:
    $key_0d9a = { 5a e8 [2] 68 ca [2] 6e ff [2] 40 ff [2] 7f e3 }

  condition:
    any of them
}