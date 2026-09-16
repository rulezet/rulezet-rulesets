rule TTP_XOR_WriteProcessMemory_badf {
  strings:
    $key_badf = { ed ad [2] df 8f [2] d9 ba [2] f7 ba [2] c8 a6 }

  condition:
    any of them
}