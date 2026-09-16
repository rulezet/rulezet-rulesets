rule TTP_XOR_WriteProcessMemory_9eed {
  strings:
    $key_9eed = { c9 9f [2] fb bd [2] fd 88 [2] d3 88 [2] ec 94 }

  condition:
    any of them
}