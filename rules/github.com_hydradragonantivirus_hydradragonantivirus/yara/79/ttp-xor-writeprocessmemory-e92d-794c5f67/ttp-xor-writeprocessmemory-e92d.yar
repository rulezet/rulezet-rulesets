rule TTP_XOR_WriteProcessMemory_e92d {
  strings:
    $key_e92d = { be 5f [2] 8c 7d [2] 8a 48 [2] a4 48 [2] 9b 54 }

  condition:
    any of them
}