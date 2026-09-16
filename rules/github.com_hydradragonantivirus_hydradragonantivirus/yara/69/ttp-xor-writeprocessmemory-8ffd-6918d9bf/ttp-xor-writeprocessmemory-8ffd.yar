rule TTP_XOR_WriteProcessMemory_8ffd {
  strings:
    $key_8ffd = { d8 8f [2] ea ad [2] ec 98 [2] c2 98 [2] fd 84 }

  condition:
    any of them
}