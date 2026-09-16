rule TTP_XOR_WriteProcessMemory_48fa {
  strings:
    $key_48fa = { 1f 88 [2] 2d aa [2] 2b 9f [2] 05 9f [2] 3a 83 }

  condition:
    any of them
}