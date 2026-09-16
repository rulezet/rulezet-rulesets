rule TTP_XOR_WriteProcessMemory_e87f {
  strings:
    $key_e87f = { bf 0d [2] 8d 2f [2] 8b 1a [2] a5 1a [2] 9a 06 }

  condition:
    any of them
}