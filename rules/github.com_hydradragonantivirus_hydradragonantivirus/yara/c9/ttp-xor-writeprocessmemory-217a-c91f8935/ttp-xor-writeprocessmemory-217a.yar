rule TTP_XOR_WriteProcessMemory_217a {
  strings:
    $key_217a = { 76 08 [2] 44 2a [2] 42 1f [2] 6c 1f [2] 53 03 }

  condition:
    any of them
}