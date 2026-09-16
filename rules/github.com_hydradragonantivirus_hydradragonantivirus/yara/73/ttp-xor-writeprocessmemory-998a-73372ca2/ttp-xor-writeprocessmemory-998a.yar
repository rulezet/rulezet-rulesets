rule TTP_XOR_WriteProcessMemory_998a {
  strings:
    $key_998a = { ce f8 [2] fc da [2] fa ef [2] d4 ef [2] eb f3 }

  condition:
    any of them
}