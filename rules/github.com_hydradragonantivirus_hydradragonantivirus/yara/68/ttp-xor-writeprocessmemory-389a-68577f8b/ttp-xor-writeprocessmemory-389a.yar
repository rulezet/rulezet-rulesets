rule TTP_XOR_WriteProcessMemory_389a {
  strings:
    $key_389a = { 6f e8 [2] 5d ca [2] 5b ff [2] 75 ff [2] 4a e3 }

  condition:
    any of them
}