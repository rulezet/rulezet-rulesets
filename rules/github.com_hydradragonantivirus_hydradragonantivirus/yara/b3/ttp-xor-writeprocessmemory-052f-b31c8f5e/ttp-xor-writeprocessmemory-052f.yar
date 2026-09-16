rule TTP_XOR_WriteProcessMemory_052f {
  strings:
    $key_052f = { 52 5d [2] 60 7f [2] 66 4a [2] 48 4a [2] 77 56 }

  condition:
    any of them
}