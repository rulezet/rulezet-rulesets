rule TTP_XOR_WriteProcessMemory_263f {
  strings:
    $key_263f = { 71 4d [2] 43 6f [2] 45 5a [2] 6b 5a [2] 54 46 }

  condition:
    any of them
}