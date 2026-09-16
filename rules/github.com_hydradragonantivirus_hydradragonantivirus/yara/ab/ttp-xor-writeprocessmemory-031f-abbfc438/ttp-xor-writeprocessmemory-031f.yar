rule TTP_XOR_WriteProcessMemory_031f {
  strings:
    $key_031f = { 54 6d [2] 66 4f [2] 60 7a [2] 4e 7a [2] 71 66 }

  condition:
    any of them
}