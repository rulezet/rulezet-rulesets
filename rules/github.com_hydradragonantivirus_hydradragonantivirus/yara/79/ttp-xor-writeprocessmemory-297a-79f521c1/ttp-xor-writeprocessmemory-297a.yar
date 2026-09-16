rule TTP_XOR_WriteProcessMemory_297a {
  strings:
    $key_297a = { 7e 08 [2] 4c 2a [2] 4a 1f [2] 64 1f [2] 5b 03 }

  condition:
    any of them
}