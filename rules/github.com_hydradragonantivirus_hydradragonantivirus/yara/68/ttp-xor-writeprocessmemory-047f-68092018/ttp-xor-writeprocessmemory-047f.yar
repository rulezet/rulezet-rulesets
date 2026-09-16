rule TTP_XOR_WriteProcessMemory_047f {
  strings:
    $key_047f = { 53 0d [2] 61 2f [2] 67 1a [2] 49 1a [2] 76 06 }

  condition:
    any of them
}