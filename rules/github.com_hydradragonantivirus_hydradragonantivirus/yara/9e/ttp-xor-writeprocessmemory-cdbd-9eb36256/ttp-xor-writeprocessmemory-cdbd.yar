rule TTP_XOR_WriteProcessMemory_cdbd {
  strings:
    $key_cdbd = { 9a cf [2] a8 ed [2] ae d8 [2] 80 d8 [2] bf c4 }

  condition:
    any of them
}