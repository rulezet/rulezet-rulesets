rule TTP_XOR_WriteProcessMemory_417d {
  strings:
    $key_417d = { 16 0f [2] 24 2d [2] 22 18 [2] 0c 18 [2] 33 04 }

  condition:
    any of them
}