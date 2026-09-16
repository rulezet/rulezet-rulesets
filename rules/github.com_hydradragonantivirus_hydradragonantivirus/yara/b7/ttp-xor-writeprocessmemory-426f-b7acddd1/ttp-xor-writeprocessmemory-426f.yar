rule TTP_XOR_WriteProcessMemory_426f {
  strings:
    $key_426f = { 15 1d [2] 27 3f [2] 21 0a [2] 0f 0a [2] 30 16 }

  condition:
    any of them
}