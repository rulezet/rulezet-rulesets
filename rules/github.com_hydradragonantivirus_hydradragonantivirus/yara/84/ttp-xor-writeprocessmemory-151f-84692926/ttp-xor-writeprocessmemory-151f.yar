rule TTP_XOR_WriteProcessMemory_151f {
  strings:
    $key_151f = { 42 6d [2] 70 4f [2] 76 7a [2] 58 7a [2] 67 66 }

  condition:
    any of them
}