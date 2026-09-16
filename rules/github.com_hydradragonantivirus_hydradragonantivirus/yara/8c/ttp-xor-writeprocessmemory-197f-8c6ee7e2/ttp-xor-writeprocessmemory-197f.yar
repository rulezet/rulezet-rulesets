rule TTP_XOR_WriteProcessMemory_197f {
  strings:
    $key_197f = { 4e 0d [2] 7c 2f [2] 7a 1a [2] 54 1a [2] 6b 06 }

  condition:
    any of them
}