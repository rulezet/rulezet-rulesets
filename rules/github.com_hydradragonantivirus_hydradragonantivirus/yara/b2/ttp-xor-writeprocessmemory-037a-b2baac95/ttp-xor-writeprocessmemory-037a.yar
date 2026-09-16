rule TTP_XOR_WriteProcessMemory_037a {
  strings:
    $key_037a = { 54 08 [2] 66 2a [2] 60 1f [2] 4e 1f [2] 71 03 }

  condition:
    any of them
}