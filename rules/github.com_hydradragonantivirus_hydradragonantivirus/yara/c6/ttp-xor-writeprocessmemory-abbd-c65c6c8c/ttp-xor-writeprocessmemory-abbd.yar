rule TTP_XOR_WriteProcessMemory_abbd {
  strings:
    $key_abbd = { fc cf [2] ce ed [2] c8 d8 [2] e6 d8 [2] d9 c4 }

  condition:
    any of them
}