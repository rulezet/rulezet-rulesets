rule TTP_XOR_WriteProcessMemory_033a {
  strings:
    $key_033a = { 54 48 [2] 66 6a [2] 60 5f [2] 4e 5f [2] 71 43 }

  condition:
    any of them
}