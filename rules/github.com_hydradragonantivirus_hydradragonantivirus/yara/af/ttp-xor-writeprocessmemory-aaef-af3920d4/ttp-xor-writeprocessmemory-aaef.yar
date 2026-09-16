rule TTP_XOR_WriteProcessMemory_aaef {
  strings:
    $key_aaef = { fd 9d [2] cf bf [2] c9 8a [2] e7 8a [2] d8 96 }

  condition:
    any of them
}