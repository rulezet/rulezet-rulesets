rule TTP_XOR_WriteProcessMemory_e81c {
  strings:
    $key_e81c = { bf 6e [2] 8d 4c [2] 8b 79 [2] a5 79 [2] 9a 65 }

  condition:
    any of them
}