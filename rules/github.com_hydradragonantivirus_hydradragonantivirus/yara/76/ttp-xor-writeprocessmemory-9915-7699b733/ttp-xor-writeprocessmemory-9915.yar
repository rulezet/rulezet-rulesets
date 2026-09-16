rule TTP_XOR_WriteProcessMemory_9915 {
  strings:
    $key_9915 = { ce 67 [2] fc 45 [2] fa 70 [2] d4 70 [2] eb 6c }

  condition:
    any of them
}