rule TTP_XOR_WriteProcessMemory_e87a {
  strings:
    $key_e87a = { bf 08 [2] 8d 2a [2] 8b 1f [2] a5 1f [2] 9a 03 }

  condition:
    any of them
}