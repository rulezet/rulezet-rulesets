rule TTP_XOR_WriteProcessMemory_552f {
  strings:
    $key_552f = { 02 5d [2] 30 7f [2] 36 4a [2] 18 4a [2] 27 56 }

  condition:
    any of them
}