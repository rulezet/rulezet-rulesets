rule TTP_XOR_WriteProcessMemory_ddbd {
  strings:
    $key_ddbd = { 8a cf [2] b8 ed [2] be d8 [2] 90 d8 [2] af c4 }

  condition:
    any of them
}