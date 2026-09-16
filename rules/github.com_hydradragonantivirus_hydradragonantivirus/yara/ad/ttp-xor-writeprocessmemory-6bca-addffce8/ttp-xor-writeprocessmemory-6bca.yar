rule TTP_XOR_WriteProcessMemory_6bca {
  strings:
    $key_6bca = { 3c b8 [2] 0e 9a [2] 08 af [2] 26 af [2] 19 b3 }

  condition:
    any of them
}