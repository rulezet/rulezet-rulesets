rule TTP_XOR_WriteProcessMemory_cbdf {
  strings:
    $key_cbdf = { 9c ad [2] ae 8f [2] a8 ba [2] 86 ba [2] b9 a6 }

  condition:
    any of them
}