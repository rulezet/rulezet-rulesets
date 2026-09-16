rule TTP_XOR_WriteProcessMemory_f92d {
  strings:
    $key_f92d = { ae 5f [2] 9c 7d [2] 9a 48 [2] b4 48 [2] 8b 54 }

  condition:
    any of them
}