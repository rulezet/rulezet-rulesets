rule TTP_XOR_WriteProcessMemory_acbd {
  strings:
    $key_acbd = { fb cf [2] c9 ed [2] cf d8 [2] e1 d8 [2] de c4 }

  condition:
    any of them
}