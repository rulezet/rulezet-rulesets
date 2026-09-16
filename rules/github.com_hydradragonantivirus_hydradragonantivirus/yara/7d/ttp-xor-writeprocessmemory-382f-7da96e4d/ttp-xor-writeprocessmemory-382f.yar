rule TTP_XOR_WriteProcessMemory_382f {
  strings:
    $key_382f = { 6f 5d [2] 5d 7f [2] 5b 4a [2] 75 4a [2] 4a 56 }

  condition:
    any of them
}