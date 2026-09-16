rule TTP_XOR_WriteProcessMemory_dadf {
  strings:
    $key_dadf = { 8d ad [2] bf 8f [2] b9 ba [2] 97 ba [2] a8 a6 }

  condition:
    any of them
}