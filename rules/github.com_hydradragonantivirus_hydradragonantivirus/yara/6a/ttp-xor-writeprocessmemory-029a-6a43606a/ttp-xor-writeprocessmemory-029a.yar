rule TTP_XOR_WriteProcessMemory_029a {
  strings:
    $key_029a = { 55 e8 [2] 67 ca [2] 61 ff [2] 4f ff [2] 70 e3 }

  condition:
    any of them
}