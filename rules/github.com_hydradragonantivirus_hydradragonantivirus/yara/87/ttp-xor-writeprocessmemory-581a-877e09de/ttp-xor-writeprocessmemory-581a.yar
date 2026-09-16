rule TTP_XOR_WriteProcessMemory_581a {
  strings:
    $key_581a = { 0f 68 [2] 3d 4a [2] 3b 7f [2] 15 7f [2] 2a 63 }

  condition:
    any of them
}