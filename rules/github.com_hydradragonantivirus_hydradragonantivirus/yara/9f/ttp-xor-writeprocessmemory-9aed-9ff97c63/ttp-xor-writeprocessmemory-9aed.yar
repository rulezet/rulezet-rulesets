rule TTP_XOR_WriteProcessMemory_9aed {
  strings:
    $key_9aed = { cd 9f [2] ff bd [2] f9 88 [2] d7 88 [2] e8 94 }

  condition:
    any of them
}