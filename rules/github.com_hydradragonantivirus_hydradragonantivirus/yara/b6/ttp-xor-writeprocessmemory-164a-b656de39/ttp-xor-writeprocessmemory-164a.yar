rule TTP_XOR_WriteProcessMemory_164a {
  strings:
    $key_164a = { 41 38 [2] 73 1a [2] 75 2f [2] 5b 2f [2] 64 33 }

  condition:
    any of them
}