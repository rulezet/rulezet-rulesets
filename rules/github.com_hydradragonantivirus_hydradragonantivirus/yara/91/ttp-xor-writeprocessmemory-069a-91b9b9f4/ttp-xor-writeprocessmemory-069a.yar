rule TTP_XOR_WriteProcessMemory_069a {
  strings:
    $key_069a = { 51 e8 [2] 63 ca [2] 65 ff [2] 4b ff [2] 74 e3 }

  condition:
    any of them
}