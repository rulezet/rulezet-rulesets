rule TTP_XOR_WriteProcessMemory_383f {
  strings:
    $key_383f = { 6f 4d [2] 5d 6f [2] 5b 5a [2] 75 5a [2] 4a 46 }

  condition:
    any of them
}