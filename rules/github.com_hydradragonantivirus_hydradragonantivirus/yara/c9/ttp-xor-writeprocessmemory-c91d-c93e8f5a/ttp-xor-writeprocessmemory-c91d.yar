rule TTP_XOR_WriteProcessMemory_c91d {
  strings:
    $key_c91d = { 9e 6f [2] ac 4d [2] aa 78 [2] 84 78 [2] bb 64 }

  condition:
    any of them
}