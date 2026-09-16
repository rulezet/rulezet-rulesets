rule TTP_XOR_WriteProcessMemory_f9ef {
  strings:
    $key_f9ef = { ae 9d [2] 9c bf [2] 9a 8a [2] b4 8a [2] 8b 96 }

  condition:
    any of them
}