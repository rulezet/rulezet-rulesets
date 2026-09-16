rule TTP_XOR_WriteProcessMemory_032f {
  strings:
    $key_032f = { 54 5d [2] 66 7f [2] 60 4a [2] 4e 4a [2] 71 56 }

  condition:
    any of them
}