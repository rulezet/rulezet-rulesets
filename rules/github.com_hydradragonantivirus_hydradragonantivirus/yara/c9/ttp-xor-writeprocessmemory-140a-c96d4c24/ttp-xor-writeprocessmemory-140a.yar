rule TTP_XOR_WriteProcessMemory_140a {
  strings:
    $key_140a = { 43 78 [2] 71 5a [2] 77 6f [2] 59 6f [2] 66 73 }

  condition:
    any of them
}