rule TTP_XOR_WriteProcessMemory_feca {
  strings:
    $key_feca = { a9 b8 [2] 9b 9a [2] 9d af [2] b3 af [2] 8c b3 }

  condition:
    any of them
}