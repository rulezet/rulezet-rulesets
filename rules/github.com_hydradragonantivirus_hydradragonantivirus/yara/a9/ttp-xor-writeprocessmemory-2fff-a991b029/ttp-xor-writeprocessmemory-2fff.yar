rule TTP_XOR_WriteProcessMemory_2fff {
  strings:
    $key_2fff = { 78 8d [2] 4a af [2] 4c 9a [2] 62 9a [2] 5d 86 }

  condition:
    any of them
}