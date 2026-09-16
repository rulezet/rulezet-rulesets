rule TTP_XOR_WriteProcessMemory_520a {
  strings:
    $key_520a = { 05 78 [2] 37 5a [2] 31 6f [2] 1f 6f [2] 20 73 }

  condition:
    any of them
}