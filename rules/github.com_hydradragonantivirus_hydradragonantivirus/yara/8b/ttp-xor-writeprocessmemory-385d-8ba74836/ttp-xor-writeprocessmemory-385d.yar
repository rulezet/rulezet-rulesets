rule TTP_XOR_WriteProcessMemory_385d {
  strings:
    $key_385d = { 6f 2f [2] 5d 0d [2] 5b 38 [2] 75 38 [2] 4a 24 }

  condition:
    any of them
}