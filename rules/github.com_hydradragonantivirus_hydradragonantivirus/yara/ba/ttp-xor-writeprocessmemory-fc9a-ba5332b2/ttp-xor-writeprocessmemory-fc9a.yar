rule TTP_XOR_WriteProcessMemory_fc9a {
  strings:
    $key_fc9a = { ab e8 [2] 99 ca [2] 9f ff [2] b1 ff [2] 8e e3 }

  condition:
    any of them
}