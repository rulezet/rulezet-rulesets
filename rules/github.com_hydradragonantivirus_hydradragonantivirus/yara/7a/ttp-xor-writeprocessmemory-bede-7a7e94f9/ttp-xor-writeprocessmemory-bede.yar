rule TTP_XOR_WriteProcessMemory_bede {
  strings:
    $key_bede = { e9 ac [2] db 8e [2] dd bb [2] f3 bb [2] cc a7 }

  condition:
    any of them
}