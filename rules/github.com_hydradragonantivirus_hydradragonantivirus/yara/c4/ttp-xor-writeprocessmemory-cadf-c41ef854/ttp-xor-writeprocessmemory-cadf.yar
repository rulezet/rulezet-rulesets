rule TTP_XOR_WriteProcessMemory_cadf {
  strings:
    $key_cadf = { 9d ad [2] af 8f [2] a9 ba [2] 87 ba [2] b8 a6 }

  condition:
    any of them
}