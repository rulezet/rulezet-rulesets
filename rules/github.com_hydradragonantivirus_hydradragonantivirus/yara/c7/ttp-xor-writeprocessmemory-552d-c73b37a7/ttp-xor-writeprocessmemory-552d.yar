rule TTP_XOR_WriteProcessMemory_552d {
  strings:
    $key_552d = { 02 5f [2] 30 7d [2] 36 48 [2] 18 48 [2] 27 54 }

  condition:
    any of them
}