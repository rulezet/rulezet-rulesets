rule TTP_XOR_WriteProcessMemory_3c9a {
  strings:
    $key_3c9a = { 6b e8 [2] 59 ca [2] 5f ff [2] 71 ff [2] 4e e3 }

  condition:
    any of them
}