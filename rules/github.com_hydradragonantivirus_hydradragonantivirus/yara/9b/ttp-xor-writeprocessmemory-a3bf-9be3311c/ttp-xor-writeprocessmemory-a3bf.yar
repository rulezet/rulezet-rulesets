rule TTP_XOR_WriteProcessMemory_a3bf {
  strings:
    $key_a3bf = { f4 cd [2] c6 ef [2] c0 da [2] ee da [2] d1 c6 }

  condition:
    any of them
}