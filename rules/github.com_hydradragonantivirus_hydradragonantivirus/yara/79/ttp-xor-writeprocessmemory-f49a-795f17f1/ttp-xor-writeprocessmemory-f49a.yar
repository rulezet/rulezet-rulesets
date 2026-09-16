rule TTP_XOR_WriteProcessMemory_f49a {
  strings:
    $key_f49a = { a3 e8 [2] 91 ca [2] 97 ff [2] b9 ff [2] 86 e3 }

  condition:
    any of them
}