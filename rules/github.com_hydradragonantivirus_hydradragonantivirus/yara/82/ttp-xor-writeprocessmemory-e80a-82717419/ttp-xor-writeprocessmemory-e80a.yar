rule TTP_XOR_WriteProcessMemory_e80a {
  strings:
    $key_e80a = { bf 78 [2] 8d 5a [2] 8b 6f [2] a5 6f [2] 9a 73 }

  condition:
    any of them
}