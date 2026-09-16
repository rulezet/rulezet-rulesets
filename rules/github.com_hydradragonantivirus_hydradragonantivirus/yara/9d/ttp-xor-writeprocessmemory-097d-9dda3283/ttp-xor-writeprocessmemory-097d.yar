rule TTP_XOR_WriteProcessMemory_097d {
  strings:
    $key_097d = { 5e 0f [2] 6c 2d [2] 6a 18 [2] 44 18 [2] 7b 04 }

  condition:
    any of them
}