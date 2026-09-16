rule TTP_XOR_WriteProcessMemory_820f {
  strings:
    $key_820f = { d5 7d [2] e7 5f [2] e1 6a [2] cf 6a [2] f0 76 }

  condition:
    any of them
}