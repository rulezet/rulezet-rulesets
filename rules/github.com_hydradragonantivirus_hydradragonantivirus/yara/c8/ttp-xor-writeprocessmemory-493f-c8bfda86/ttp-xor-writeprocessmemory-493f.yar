rule TTP_XOR_WriteProcessMemory_493f {
  strings:
    $key_493f = { 1e 4d [2] 2c 6f [2] 2a 5a [2] 04 5a [2] 3b 46 }

  condition:
    any of them
}