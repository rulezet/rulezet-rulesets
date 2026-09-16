rule TTP_XOR_WriteProcessMemory_9933 {
  strings:
    $key_9933 = { ce 41 [2] fc 63 [2] fa 56 [2] d4 56 [2] eb 4a }

  condition:
    any of them
}