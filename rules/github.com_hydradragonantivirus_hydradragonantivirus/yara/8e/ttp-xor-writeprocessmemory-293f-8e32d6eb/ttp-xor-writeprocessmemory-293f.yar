rule TTP_XOR_WriteProcessMemory_293f {
  strings:
    $key_293f = { 7e 4d [2] 4c 6f [2] 4a 5a [2] 64 5a [2] 5b 46 }

  condition:
    any of them
}