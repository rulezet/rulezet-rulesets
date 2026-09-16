rule TTP_XOR_WriteProcessMemory_040f {
  strings:
    $key_040f = { 53 7d [2] 61 5f [2] 67 6a [2] 49 6a [2] 76 76 }

  condition:
    any of them
}