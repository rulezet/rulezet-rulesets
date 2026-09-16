rule TTP_XOR_WriteProcessMemory_321d {
  strings:
    $key_321d = { 65 6f [2] 57 4d [2] 51 78 [2] 7f 78 [2] 40 64 }

  condition:
    any of them
}