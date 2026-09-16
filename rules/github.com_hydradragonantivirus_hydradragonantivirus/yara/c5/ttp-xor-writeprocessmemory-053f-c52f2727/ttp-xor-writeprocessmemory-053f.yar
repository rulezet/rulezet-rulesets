rule TTP_XOR_WriteProcessMemory_053f {
  strings:
    $key_053f = { 52 4d [2] 60 6f [2] 66 5a [2] 48 5a [2] 77 46 }

  condition:
    any of them
}