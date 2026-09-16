rule TTP_XOR_WriteProcessMemory_9acb {
  strings:
    $key_9acb = { cd b9 [2] ff 9b [2] f9 ae [2] d7 ae [2] e8 b2 }

  condition:
    any of them
}