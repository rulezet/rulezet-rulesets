rule TTP_XOR_WriteProcessMemory_09fa {
  strings:
    $key_09fa = { 5e 88 [2] 6c aa [2] 6a 9f [2] 44 9f [2] 7b 83 }

  condition:
    any of them
}