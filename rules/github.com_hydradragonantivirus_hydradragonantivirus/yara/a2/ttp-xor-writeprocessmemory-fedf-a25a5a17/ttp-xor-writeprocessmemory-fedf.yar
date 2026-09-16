rule TTP_XOR_WriteProcessMemory_fedf {
  strings:
    $key_fedf = { a9 ad [2] 9b 8f [2] 9d ba [2] b3 ba [2] 8c a6 }

  condition:
    any of them
}