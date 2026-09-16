rule TTP_XOR_WriteProcessMemory_f95d {
  strings:
    $key_f95d = { ae 2f [2] 9c 0d [2] 9a 38 [2] b4 38 [2] 8b 24 }

  condition:
    any of them
}