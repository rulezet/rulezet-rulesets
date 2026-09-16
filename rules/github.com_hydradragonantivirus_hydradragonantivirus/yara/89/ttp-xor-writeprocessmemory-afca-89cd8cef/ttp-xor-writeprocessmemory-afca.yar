rule TTP_XOR_WriteProcessMemory_afca {
  strings:
    $key_afca = { f8 b8 [2] ca 9a [2] cc af [2] e2 af [2] dd b3 }

  condition:
    any of them
}