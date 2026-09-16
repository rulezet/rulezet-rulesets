rule TTP_XOR_WriteProcessMemory_e82a {
  strings:
    $key_e82a = { bf 58 [2] 8d 7a [2] 8b 4f [2] a5 4f [2] 9a 53 }

  condition:
    any of them
}