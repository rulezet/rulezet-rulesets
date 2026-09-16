rule TTP_XOR_WriteProcessMemory_173f {
  strings:
    $key_173f = { 40 4d [2] 72 6f [2] 74 5a [2] 5a 5a [2] 65 46 }

  condition:
    any of them
}