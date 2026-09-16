rule TTP_XOR_WriteProcessMemory_9934 {
  strings:
    $key_9934 = { ce 46 [2] fc 64 [2] fa 51 [2] d4 51 [2] eb 4d }

  condition:
    any of them
}