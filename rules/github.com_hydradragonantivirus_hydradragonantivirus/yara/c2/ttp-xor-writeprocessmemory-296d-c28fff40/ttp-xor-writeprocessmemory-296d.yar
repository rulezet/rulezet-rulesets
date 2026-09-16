rule TTP_XOR_WriteProcessMemory_296d {
  strings:
    $key_296d = { 7e 1f [2] 4c 3d [2] 4a 08 [2] 64 08 [2] 5b 14 }

  condition:
    any of them
}