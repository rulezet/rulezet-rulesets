rule TTP_XOR_WriteProcessMemory_dc9a {
  strings:
    $key_dc9a = { 8b e8 [2] b9 ca [2] bf ff [2] 91 ff [2] ae e3 }

  condition:
    any of them
}