rule TTP_XOR_WriteProcessMemory_9935 {
  strings:
    $key_9935 = { ce 47 [2] fc 65 [2] fa 50 [2] d4 50 [2] eb 4c }

  condition:
    any of them
}