rule TTP_XOR_WriteProcessMemory_43ca {
  strings:
    $key_43ca = { 14 b8 [2] 26 9a [2] 20 af [2] 0e af [2] 31 b3 }

  condition:
    any of them
}