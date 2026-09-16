rule TTP_XOR_WriteProcessMemory_9954 {
  strings:
    $key_9954 = { ce 26 [2] fc 04 [2] fa 31 [2] d4 31 [2] eb 2d }

  condition:
    any of them
}