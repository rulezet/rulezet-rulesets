rule TTP_XOR_WriteProcessMemory_085d {
  strings:
    $key_085d = { 5f 2f [2] 6d 0d [2] 6b 38 [2] 45 38 [2] 7a 24 }

  condition:
    any of them
}