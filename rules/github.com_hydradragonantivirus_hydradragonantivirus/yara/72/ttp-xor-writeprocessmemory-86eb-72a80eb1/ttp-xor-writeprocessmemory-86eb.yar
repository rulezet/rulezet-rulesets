rule TTP_XOR_WriteProcessMemory_86eb {
  strings:
    $key_86eb = { d1 99 [2] e3 bb [2] e5 8e [2] cb 8e [2] f4 92 }

  condition:
    any of them
}