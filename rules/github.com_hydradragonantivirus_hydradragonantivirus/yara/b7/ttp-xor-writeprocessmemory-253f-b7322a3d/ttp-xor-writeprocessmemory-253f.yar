rule TTP_XOR_WriteProcessMemory_253f {
  strings:
    $key_253f = { 72 4d [2] 40 6f [2] 46 5a [2] 68 5a [2] 57 46 }

  condition:
    any of them
}