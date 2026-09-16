rule TTP_XOR_WriteProcessMemory_200d {
  strings:
    $key_200d = { 77 7f [2] 45 5d [2] 43 68 [2] 6d 68 [2] 52 74 }

  condition:
    any of them
}