rule TTP_XOR_WriteProcessMemory_137a {
  strings:
    $key_137a = { 44 08 [2] 76 2a [2] 70 1f [2] 5e 1f [2] 61 03 }

  condition:
    any of them
}