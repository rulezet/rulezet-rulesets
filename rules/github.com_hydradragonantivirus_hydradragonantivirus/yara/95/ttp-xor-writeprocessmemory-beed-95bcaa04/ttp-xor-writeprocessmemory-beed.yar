rule TTP_XOR_WriteProcessMemory_beed {
  strings:
    $key_beed = { e9 9f [2] db bd [2] dd 88 [2] f3 88 [2] cc 94 }

  condition:
    any of them
}