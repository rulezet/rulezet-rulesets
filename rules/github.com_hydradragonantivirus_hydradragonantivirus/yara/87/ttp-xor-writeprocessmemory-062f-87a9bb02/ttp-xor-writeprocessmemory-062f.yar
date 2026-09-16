rule TTP_XOR_WriteProcessMemory_062f {
  strings:
    $key_062f = { 51 5d [2] 63 7f [2] 65 4a [2] 4b 4a [2] 74 56 }

  condition:
    any of them
}