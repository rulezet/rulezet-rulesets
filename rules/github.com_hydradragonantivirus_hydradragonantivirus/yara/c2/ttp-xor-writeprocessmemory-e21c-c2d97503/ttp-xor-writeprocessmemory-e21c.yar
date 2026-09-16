rule TTP_XOR_WriteProcessMemory_e21c {
  strings:
    $key_e21c = { b5 6e [2] 87 4c [2] 81 79 [2] af 79 [2] 90 65 }

  condition:
    any of them
}