rule TTP_XOR_WriteProcessMemory_211d {
  strings:
    $key_211d = { 76 6f [2] 44 4d [2] 42 78 [2] 6c 78 [2] 53 64 }

  condition:
    any of them
}