rule TTP_XOR_WriteProcessMemory_e21d {
  strings:
    $key_e21d = { b5 6f [2] 87 4d [2] 81 78 [2] af 78 [2] 90 64 }

  condition:
    any of them
}