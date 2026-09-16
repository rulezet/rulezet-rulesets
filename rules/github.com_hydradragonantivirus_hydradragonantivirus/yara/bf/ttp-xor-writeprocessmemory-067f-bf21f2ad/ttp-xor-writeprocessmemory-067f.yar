rule TTP_XOR_WriteProcessMemory_067f {
  strings:
    $key_067f = { 51 0d [2] 63 2f [2] 65 1a [2] 4b 1a [2] 74 06 }

  condition:
    any of them
}