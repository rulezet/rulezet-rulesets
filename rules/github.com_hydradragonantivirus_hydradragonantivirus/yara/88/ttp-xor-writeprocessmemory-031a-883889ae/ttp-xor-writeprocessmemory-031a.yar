rule TTP_XOR_WriteProcessMemory_031a {
  strings:
    $key_031a = { 54 68 [2] 66 4a [2] 60 7f [2] 4e 7f [2] 71 63 }

  condition:
    any of them
}