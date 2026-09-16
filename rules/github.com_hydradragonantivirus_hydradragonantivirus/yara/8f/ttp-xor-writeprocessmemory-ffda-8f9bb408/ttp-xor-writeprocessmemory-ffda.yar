rule TTP_XOR_WriteProcessMemory_ffda {
  strings:
    $key_ffda = { a8 a8 [2] 9a 8a [2] 9c bf [2] b2 bf [2] 8d a3 }

  condition:
    any of them
}