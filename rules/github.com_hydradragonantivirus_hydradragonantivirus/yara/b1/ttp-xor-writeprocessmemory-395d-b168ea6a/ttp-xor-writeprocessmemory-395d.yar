rule TTP_XOR_WriteProcessMemory_395d {
  strings:
    $key_395d = { 6e 2f [2] 5c 0d [2] 5a 38 [2] 74 38 [2] 4b 24 }

  condition:
    any of them
}