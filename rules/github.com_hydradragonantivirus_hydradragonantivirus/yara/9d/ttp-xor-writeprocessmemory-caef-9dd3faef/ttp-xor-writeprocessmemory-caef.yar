rule TTP_XOR_WriteProcessMemory_caef {
  strings:
    $key_caef = { 9d 9d [2] af bf [2] a9 8a [2] 87 8a [2] b8 96 }

  condition:
    any of them
}