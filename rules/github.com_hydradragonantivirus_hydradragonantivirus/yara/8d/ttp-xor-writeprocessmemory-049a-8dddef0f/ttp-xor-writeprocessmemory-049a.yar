rule TTP_XOR_WriteProcessMemory_049a {
  strings:
    $key_049a = { 53 e8 [2] 61 ca [2] 67 ff [2] 49 ff [2] 76 e3 }

  condition:
    any of them
}