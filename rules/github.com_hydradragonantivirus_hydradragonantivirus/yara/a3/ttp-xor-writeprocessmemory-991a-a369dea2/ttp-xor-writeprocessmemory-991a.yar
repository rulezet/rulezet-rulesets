rule TTP_XOR_WriteProcessMemory_991a {
  strings:
    $key_991a = { ce 68 [2] fc 4a [2] fa 7f [2] d4 7f [2] eb 63 }

  condition:
    any of them
}