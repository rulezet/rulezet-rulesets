rule TTP_XOR_WriteProcessMemory_313f {
  strings:
    $key_313f = { 66 4d [2] 54 6f [2] 52 5a [2] 7c 5a [2] 43 46 }

  condition:
    any of them
}