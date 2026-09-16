rule TTP_XOR_WriteProcessMemory_9e88 {
  strings:
    $key_9e88 = { c9 fa [2] fb d8 [2] fd ed [2] d3 ed [2] ec f1 }

  condition:
    any of them
}