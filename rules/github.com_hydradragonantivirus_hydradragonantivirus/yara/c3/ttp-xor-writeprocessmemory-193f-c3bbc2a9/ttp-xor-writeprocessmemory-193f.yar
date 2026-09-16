rule TTP_XOR_WriteProcessMemory_193f {
  strings:
    $key_193f = { 4e 4d [2] 7c 6f [2] 7a 5a [2] 54 5a [2] 6b 46 }

  condition:
    any of them
}