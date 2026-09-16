rule TTP_XOR_WriteProcessMemory_372f {
  strings:
    $key_372f = { 60 5d [2] 52 7f [2] 54 4a [2] 7a 4a [2] 45 56 }

  condition:
    any of them
}