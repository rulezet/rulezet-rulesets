rule TTP_XOR_WriteProcessMemory_3fff {
  strings:
    $key_3fff = { 68 8d [2] 5a af [2] 5c 9a [2] 72 9a [2] 4d 86 }

  condition:
    any of them
}