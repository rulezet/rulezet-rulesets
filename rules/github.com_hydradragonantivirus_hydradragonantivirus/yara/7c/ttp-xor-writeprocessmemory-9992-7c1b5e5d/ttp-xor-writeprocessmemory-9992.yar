rule TTP_XOR_WriteProcessMemory_9992 {
  strings:
    $key_9992 = { ce e0 [2] fc c2 [2] fa f7 [2] d4 f7 [2] eb eb }

  condition:
    any of them
}