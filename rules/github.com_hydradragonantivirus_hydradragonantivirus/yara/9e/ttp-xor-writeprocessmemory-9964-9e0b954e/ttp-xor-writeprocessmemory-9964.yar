rule TTP_XOR_WriteProcessMemory_9964 {
  strings:
    $key_9964 = { ce 16 [2] fc 34 [2] fa 01 [2] d4 01 [2] eb 1d }

  condition:
    any of them
}