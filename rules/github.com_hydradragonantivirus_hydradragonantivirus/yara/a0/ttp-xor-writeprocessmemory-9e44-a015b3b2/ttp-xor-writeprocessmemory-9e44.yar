rule TTP_XOR_WriteProcessMemory_9e44 {
  strings:
    $key_9e44 = { c9 36 [2] fb 14 [2] fd 21 [2] d3 21 [2] ec 3d }

  condition:
    any of them
}