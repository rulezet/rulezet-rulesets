rule TTP_XOR_WriteProcessMemory_979a {
  strings:
    $key_979a = { c0 e8 [2] f2 ca [2] f4 ff [2] da ff [2] e5 e3 }

  condition:
    any of them
}