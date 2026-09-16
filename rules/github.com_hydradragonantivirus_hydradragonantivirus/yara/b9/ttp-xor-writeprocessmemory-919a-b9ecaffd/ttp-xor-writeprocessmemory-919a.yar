rule TTP_XOR_WriteProcessMemory_919a {
  strings:
    $key_919a = { c6 e8 [2] f4 ca [2] f2 ff [2] dc ff [2] e3 e3 }

  condition:
    any of them
}