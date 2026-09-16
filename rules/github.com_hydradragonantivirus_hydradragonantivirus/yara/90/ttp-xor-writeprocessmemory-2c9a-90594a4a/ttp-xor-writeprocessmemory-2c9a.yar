rule TTP_XOR_WriteProcessMemory_2c9a {
  strings:
    $key_2c9a = { 7b e8 [2] 49 ca [2] 4f ff [2] 61 ff [2] 5e e3 }

  condition:
    any of them
}