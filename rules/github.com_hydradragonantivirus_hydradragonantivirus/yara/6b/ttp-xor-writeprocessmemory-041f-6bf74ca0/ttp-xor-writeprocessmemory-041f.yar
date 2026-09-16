rule TTP_XOR_WriteProcessMemory_041f {
  strings:
    $key_041f = { 53 6d [2] 61 4f [2] 67 7a [2] 49 7a [2] 76 66 }

  condition:
    any of them
}