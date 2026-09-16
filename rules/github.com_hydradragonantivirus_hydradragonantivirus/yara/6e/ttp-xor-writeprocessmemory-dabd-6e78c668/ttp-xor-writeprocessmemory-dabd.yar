rule TTP_XOR_WriteProcessMemory_dabd {
  strings:
    $key_dabd = { 8d cf [2] bf ed [2] b9 d8 [2] 97 d8 [2] a8 c4 }

  condition:
    any of them
}