rule TTP_XOR_WriteProcessMemory_b9de {
  strings:
    $key_b9de = { ee ac [2] dc 8e [2] da bb [2] f4 bb [2] cb a7 }

  condition:
    any of them
}