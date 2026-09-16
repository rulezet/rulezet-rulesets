rule TTP_XOR_WriteProcessMemory_dbef {
  strings:
    $key_dbef = { 8c 9d [2] be bf [2] b8 8a [2] 96 8a [2] a9 96 }

  condition:
    any of them
}