rule TTP_XOR_WriteProcessMemory_051a {
  strings:
    $key_051a = { 52 68 [2] 60 4a [2] 66 7f [2] 48 7f [2] 77 63 }

  condition:
    any of them
}